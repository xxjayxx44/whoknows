// bitcoin_scanner.cpp

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>

#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <secp256k1.h>

namespace fs = std::filesystem;

// Base58 alphabet for encoding
static const char* BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Build a reverse map for Base58 decoding
static int8_t B58_MAP[256];
struct _InitB58 {
    _InitB58() {
        std::fill(std::begin(B58_MAP), std::end(B58_MAP), -1);
        for (int i = 0; BASE58_ALPHABET[i]; ++i) {
            B58_MAP[(uint8_t)BASE58_ALPHABET[i]] = i;
        }
    }
} _initB58;

// Limits
constexpr size_t MAX_FUNDED_ADDRESSES = 100000;

// Fast XorShift64* RNG
struct XorShift64 {
    uint64_t state;
    XorShift64(uint64_t seed)
        : state(seed ? seed : 0xdeadbeefcafebabeULL) {}
    inline uint64_t next() {
        uint64_t x = state;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        return state = x * 0x2545F4914F6CDD1DULL;
    }
};

// Progress counters
std::atomic<uint64_t> total_checked{0};
std::atomic<uint64_t> funded_loaded{0};
std::mutex file_mutex;

// Decode Base58Check into raw bytes; returns empty vector on error
std::vector<unsigned char> decodeBase58Check(const std::string& addr) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BN_zero(bn);

    for (char c : addr) {
        int8_t v = (c < 0 || c > 127) ? -1 : B58_MAP[(uint8_t)c];
        if (v < 0) { BN_free(bn); BN_CTX_free(ctx); return {}; }
        BN_mul_word(bn, 58);
        BN_add_word(bn, v);
    }

    // Convert BN to binary
    int num_bytes = BN_num_bytes(bn);
    std::vector<unsigned char> bin(num_bytes);
    BN_bn2bin(bn, bin.data());

    // Count leading '1's for leading zero bytes
    size_t zeros = 0;
    for (char c : addr) {
        if (c == '1') zeros++;
        else break;
    }

    // Prepend zeros
    std::vector<unsigned char> result(zeros + bin.size());
    std::fill(result.begin(), result.begin() + zeros, 0);
    std::copy(bin.begin(), bin.end(), result.begin() + zeros);

    BN_free(bn);
    BN_CTX_free(ctx);

    // Must be at least version(1)+payload(20)+checksum(4)=25 bytes
    if (result.size() < 25) return {};

    // Verify checksum
    size_t len = result.size();
    unsigned char hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
    SHA256(result.data(), len - 4, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    if (memcmp(hash2, result.data() + len - 4, 4) != 0) return {};

    // Return the payload: version + data (we include version for completeness)
    return result;
}

// Reservoir sampling from a plain TSV
void reservoirSampleTxt(const std::string& path, std::vector<std::string>& reservoir) {
    std::ifstream in(path);
    if (!in) { std::cerr<<"Error: cannot open "<<path<<"\n"; std::exit(1); }
    std::string line;
    size_t count = 0;
    std::mt19937_64 gen(std::random_device{}());
    while (std::getline(in, line)) {
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab != std::string::npos) line.resize(tab);
        if (reservoir.size() < MAX_FUNDED_ADDRESSES) {
            reservoir.push_back(line);
        } else {
            std::uniform_int_distribution<size_t> dist(0, count);
            size_t idx = dist(gen);
            if (idx < MAX_FUNDED_ADDRESSES) reservoir[idx] = line;
        }
        ++count;
    }
}

// Reservoir sampling from a gzipped TSV
void reservoirSampleGz(const std::string& path, std::vector<std::string>& reservoir) {
    gzFile gz = gzopen(path.c_str(), "rb");
    if (!gz) { std::cerr<<"Error: cannot open gz file: "<<path<<"\n"; std::exit(1); }
    constexpr int BUF = 1<<20;
    char buf[BUF];
    size_t count = 0;
    std::mt19937_64 gen(std::random_device{}());
    while (gzgets(gz, buf, BUF)) {
        std::string line(buf);
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab != std::string::npos) line.resize(tab);
        if (reservoir.size() < MAX_FUNDED_ADDRESSES) {
            reservoir.push_back(line);
        } else {
            std::uniform_int_distribution<size_t> dist(0, count);
            size_t idx = dist(gen);
            if (idx < MAX_FUNDED_ADDRESSES) reservoir[idx] = line;
        }
        ++count;
    }
    gzclose(gz);
}

// Load funded addresses into a set of raw 20-byte hash160 payloads
std::unordered_set<std::array<uint8_t,20>> loadFunded(const std::string& path) {
    // 1) Reservoir sample the addresses as strings
    std::vector<std::string> reservoir;
    reservoir.reserve(MAX_FUNDED_ADDRESSES);
    if (path.size()>3 && path.substr(path.size()-3)==".gz")
        reservoirSampleGz(path, reservoir);
    else
        reservoirSampleTxt(path, reservoir);

    // 2) Decode each to raw bytes and extract hash160
    std::unordered_set<std::array<uint8_t,20>> s;
    s.reserve(reservoir.size());
    for (auto& addr : reservoir) {
        auto raw = decodeBase58Check(addr);
        if (raw.size() >= 21 && raw[0] == 0x00) {
            std::array<uint8_t,20> h;
            memcpy(h.data(), raw.data()+1, 20);
            s.insert(h);
        }
    }
    funded_loaded.store(s.size(), std::memory_order_relaxed);
    return s;
}

// SHA256→RIPEMD160
inline void hash160(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), sha);
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, out);
}

// Base58Check encode (for logging only)
std::string base58CheckEncode(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> buf = data;
    unsigned char sha1[SHA256_DIGEST_LENGTH], sha2[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), sha1);
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    buf.insert(buf.end(), sha2, sha2+4);

    // Leading zeros
    size_t zeros = 0;
    while (zeros < buf.size() && buf[zeros]==0) ++zeros;

    // Convert
    std::vector<unsigned char> temp(buf.begin(), buf.end());
    std::string res; res.reserve(buf.size()*138/100 + 1);
    size_t start = zeros;
    while (start < temp.size()) {
        int carry = 0;
        for (size_t i = start; i < temp.size(); ++i) {
            int v = (carry << 8) + temp[i];
            temp[i] = v / 58;
            carry = v % 58;
        }
        res.push_back(BASE58_ALPHABET[carry]);
        while (start < temp.size() && temp[start]==0) ++start;
    }
    for (size_t i = 0; i < zeros; ++i) res.push_back('1');
    std::reverse(res.begin(), res.end());
    return res;
}

// Derive addresses, check raw hash160, log matches
void derive_and_check(
    const std::vector<unsigned char>& priv,
    secp256k1_context* ctx,
    const std::unordered_set<std::array<uint8_t,20>>& funded,
    std::ofstream& out)
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv.data())) return;

    // Uncompressed
    unsigned char buf1[65]; size_t l1=65;
    secp256k1_ec_pubkey_serialize(ctx, buf1, &l1, &pub, SECP256K1_EC_UNCOMPRESSED);
    std::vector<unsigned char> v1(buf1, buf1+l1);
    unsigned char h1[20]; hash160(v1, h1);
    std::array<uint8_t,20> key1;
    memcpy(key1.data(), h1, 20);

    // Compressed
    unsigned char buf2[33]; size_t l2=33;
    secp256k1_ec_pubkey_serialize(ctx, buf2, &l2, &pub, SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> v2(buf2, buf2+l2);
    unsigned char h2[20]; hash160(v2, h2);
    std::array<uint8_t,20> key2;
    memcpy(key2.data(), h2, 20);

    // Check
    if (funded.count(key1) || funded.count(key2)) {
        std::lock_guard<std::mutex> g(file_mutex);
        // Log both pubkey forms
        if (funded.count(key1)) {
            auto addr = base58CheckEncode({0x00, h1, h1+20});
            out << addr << " PRIV:";
            for (auto c : priv) out << std::hex << (int)c;
            out << "\n";
        }
        if (funded.count(key2)) {
            auto addr = base58CheckEncode({0x00, h2, h2+20});
            out << addr << " PRIV:";
            for (auto c : priv) out << std::hex << (int)c;
            out << "\n";
        }
    }
}

// Worker thread
void worker(const std::unordered_set<std::array<uint8_t,20>>& funded) {
    XorShift64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id())
                   ^ std::random_device{}());
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::ofstream out("addresses.txt", std::ios::app);
    std::vector<unsigned char> priv(32);
    uint64_t local = 0;

    while (true) {
        for (int i = 0; i < 4; ++i) {
            uint64_t r = rng.next();
            for (int b = 0; b < 8; ++b)
                priv[i*8 + b] = (r >> (8*b)) & 0xFF;
        }
        derive_and_check(priv, ctx, funded, out);
        if (++local >= 1024) {
            total_checked.fetch_add(local, std::memory_order_relaxed);
            local = 0;
        }
    }
}

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    const std::string fname = "bitcoin_addresses_latest.tsv";
    std::vector<std::string> candidates;
    if (argc>1) candidates.push_back(argv[1]);
    candidates.push_back(fname);
    candidates.push_back(fname + ".gz");
    candidates.push_back("/mnt/c/Users/jjmor/Downloads/" + fname);
    candidates.push_back("/mnt/c/Users/jjmor/Downloads/" + fname + ".gz");
    if (auto* h = std::getenv("HOME")) {
        candidates.push_back(std::string(h) + "/" + fname);
        candidates.push_back(std::string(h) + "/" + fname + ".gz");
    }

    std::string path;
    for (auto& p : candidates) {
        if (fs::exists(p) && fs::is_regular_file(p)) { path = p; break; }
    }
    if (path.empty()) {
        std::cerr << "Error: cannot find " << fname << "(.gz)\n";
        return 1;
    }

    std::cout << "[*] Loading funded addresses...\n";
    auto funded = loadFunded(path);
    std::cout << "[+] Loaded funded addresses: " << funded_loaded.load() << "\n";
    if (funded.empty()) {
        std::cerr << "No addresses loaded - check file format.\n";
        return 1;
    }

    // Progress reporter
    std::thread reporter([&](){
        uint64_t prev = 0;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t now = total_checked.load();
            std::cout << "[*] Checked " << now << " keys (+" << (now-prev) << "/s)\n";
            prev = now;
        }
    });
    reporter.detach();

    // Workers
    unsigned int n = std::max(1u, std::thread::hardware_concurrency() - 1);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < n; ++i)
        threads.emplace_back(worker, std::cref(funded));
    for (auto& t : threads) t.join();

    return 0;
}
