// bitcoin_scanner.cpp

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>

#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <secp256k1.h>

namespace fs = std::filesystem;

// Custom hash specialization for std::array<unsigned char, 20>
namespace std {
    template<>
    struct hash<std::array<unsigned char, 20>> {
        size_t operator()(const std::array<unsigned char, 20>& arr) const noexcept {
            size_t h = 0;
            for (auto b : arr) {
                h ^= std::hash<unsigned char>{}(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            return h;
        }
    };
}

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

// Configuration
constexpr size_t MAX_FUNDED_ADDRESSES = 100000;
constexpr size_t PRIV_BATCH_SIZE = 1024;
constexpr size_t ALIGNMENT = 64;

// Progress counters
alignas(ALIGNMENT) std::atomic<uint64_t> total_checked{0};
alignas(ALIGNMENT) std::atomic<uint64_t> funded_loaded{0};
std::mutex file_mutex;

// Optimized Base58 decoder
std::vector<unsigned char> decodeBase58Check(const std::string& addr) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BN_zero(bn);

    for (char c : addr) {
        uint8_t uc = static_cast<uint8_t>(c);
        int8_t v = B58_MAP[uc];
        if (v < 0) { BN_free(bn); BN_CTX_free(ctx); return {}; }
        BN_mul_word(bn, 58);
        BN_add_word(bn, v);
    }

    int num_bytes = BN_num_bytes(bn);
    std::vector<unsigned char> bin(num_bytes);
    BN_bn2bin(bn, bin.data());

    size_t zeros = 0;
    for (char c : addr) {
        if (c == '1') zeros++;
        else break;
    }

    std::vector<unsigned char> result(zeros + bin.size());
    std::fill(result.begin(), result.begin() + zeros, 0);
    std::copy(bin.begin(), bin.end(), result.begin() + zeros);

    BN_free(bn);
    BN_CTX_free(ctx);

    if (result.size() < 25) return {};

    unsigned char hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
    SHA256(result.data(), result.size() - 4, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    
    if (memcmp(hash2, result.data() + result.size() - 4, 4) != 0) return {};
    return {result.begin(), result.end() - 4};
}

// Reservoir sampling from plain TSV
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

// Reservoir sampling from gzipped TSV
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

// Load funded addresses
std::unordered_set<std::array<unsigned char, 20>> loadFunded(const std::string& path) {
    std::vector<std::string> reservoir;
    reservoir.reserve(MAX_FUNDED_ADDRESSES);
    if (path.size()>3 && path.substr(path.size()-3)==".gz")
        reservoirSampleGz(path, reservoir);
    else
        reservoirSampleTxt(path, reservoir);

    std::unordered_set<std::array<unsigned char, 20>> s;
    s.reserve(reservoir.size());
    for (auto& addr : reservoir) {
        auto raw = decodeBase58Check(addr);
        if (raw.size() >= 21 && raw[0] == 0x00) {
            std::array<unsigned char, 20> h;
            memcpy(h.data(), raw.data()+1, 20);
            s.insert(h);
        }
    }
    funded_loaded.store(s.size(), std::memory_order_relaxed);
    return s;
}

// Optimized hash160 using EVP
inline void hash160(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), sha);
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(ctx, sha, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ctx, out, nullptr);
    EVP_MD_CTX_free(ctx);
}

// Base58Check encode
std::string base58CheckEncode(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> buf = data;
    unsigned char sha1[SHA256_DIGEST_LENGTH], sha2[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), sha1);
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    buf.insert(buf.end(), sha2, sha2+4);

    size_t zeros = 0;
    while (zeros < buf.size() && buf[zeros]==0) ++zeros;

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

// Batch processing function
void derive_and_check_batch(
    const std::vector<unsigned char>& priv_batch,
    secp256k1_context* ctx,
    const std::unordered_set<std::array<unsigned char, 20>>& funded,
    std::ofstream& out)
{
    const size_t batch_size = priv_batch.size() / 32;
    
    #pragma omp parallel for
    for (size_t i = 0; i < batch_size; ++i) {
        const unsigned char* priv = priv_batch.data() + i * 32;
        secp256k1_pubkey pub;
        
        if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) continue;

        unsigned char buf1[65], buf2[33];
        size_t len1 = 65, len2 = 33;
        
        secp256k1_ec_pubkey_serialize(ctx, buf1, &len1, &pub, SECP256K1_EC_UNCOMPRESSED);
        secp256k1_ec_pubkey_serialize(ctx, buf2, &len2, &pub, SECP256K1_EC_COMPRESSED);

        unsigned char h1[20], h2[20];
        hash160(std::vector<unsigned char>(buf1, buf1+len1), h1);
        hash160(std::vector<unsigned char>(buf2, buf2+len2), h2);

        std::array<unsigned char, 20> key1, key2;
        memcpy(key1.data(), h1, 20);
        memcpy(key2.data(), h2, 20);

        if (funded.count(key1) || funded.count(key2)) {
            std::lock_guard<std::mutex> lock(file_mutex);
            if (funded.count(key1)) {
                std::vector<unsigned char> data{0x00};
                data.insert(data.end(), h1, h1+20);
                out << base58CheckEncode(data) << " PRIV:";
                for (int j = 0; j < 32; ++j) 
                    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(priv[j]);
                out << "\n";
            }
            if (funded.count(key2)) {
                std::vector<unsigned char> data{0x00};
                data.insert(data.end(), h2, h2+20);
                out << base58CheckEncode(data) << " PRIV:";
                for (int j = 0; j < 32; ++j) 
                    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(priv[j]);
                out << "\n";
            }
        }
    }
}

// Optimized worker thread
void worker(const std::unordered_set<std::array<unsigned char, 20>>& funded) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::ofstream out("addresses.txt", std::ios::app);
    alignas(ALIGNMENT) std::vector<unsigned char> priv_batch(PRIV_BATCH_SIZE * 32);

    #ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    #endif

    while (true) {
        if (RAND_bytes(priv_batch.data(), priv_batch.size()) != 1) {
            std::cerr << "RAND_bytes failed\n";
            break;
        }

        derive_and_check_batch(priv_batch, ctx, funded, out);
        total_checked.fetch_add(PRIV_BATCH_SIZE, std::memory_order_relaxed);
    }
}

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // Initialize RNG
    if (RAND_status() != 1) {
        std::vector<unsigned char> seed(256);
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (!urandom) {
            std::cerr << "Failed to initialize secure RNG\n";
            return 1;
        }
        urandom.read(reinterpret_cast<char*>(seed.data()), seed.size());
        RAND_seed(seed.data(), seed.size());
    }

    // Find input file
    const std::string fname = "bitcoin_addresses_latest.tsv";
    std::vector<std::string> candidates;
    if (argc > 1) candidates.push_back(argv[1]);
    candidates.insert(candidates.end(), {
        fname, fname + ".gz",
        "/mnt/c/Users/jjmor/Downloads/" + fname,
        "/mnt/c/Users/jjmor/Downloads/" + fname + ".gz"
    });
    
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

    // Load funded addresses
    std::cout << "[*] Loading funded addresses...\n";
    auto funded = loadFunded(path);
    std::cout << "[+] Loaded funded addresses: " << funded_loaded.load() << "\n";
    if (funded.empty()) {
        std::cerr << "No addresses loaded - check file format.\n";
        return 1;
    }

    // Start workers
    unsigned int n = std::max(1u, std::thread::hardware_concurrency() - 1);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < n; ++i)
        threads.emplace_back(worker, std::cref(funded));

    // Progress reporting
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

    for (auto& t : threads) t.join();
    return 0;
}
