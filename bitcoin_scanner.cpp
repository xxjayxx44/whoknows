// bitcoin_scanner.cpp

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

// Base58 alphabet
static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Fast xorshift64* RNG
struct XorShift64 {
    uint64_t state;
    XorShift64(uint64_t seed) : state(seed ? seed : 0xdeadbeefcafebabeULL) {}
    uint64_t next() {
        uint64_t x = state;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }
};

// Atomic counter for progress
std::atomic<uint64_t> total_checked{0};
std::mutex file_mutex;

// Load funded addresses from a (possibly two‑column) TSV into a set
std::unordered_set<std::string> loadFunded(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "Error: could not open funded file: " << path << "\n";
        std::exit(1);
    }
    std::unordered_set<std::string> s;
    s.reserve(5'000'000); // tune to your file size
    std::string line;
    while (std::getline(in, line)) {
        // strip CR/LF
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (line.empty()) continue;
        // if TSV with two columns, split on tab
        auto tab = line.find('\t');
        if (tab != std::string::npos) line.resize(tab);
        s.insert(line);
    }
    return s;
}

// SHA256→RIPEMD160 (hash160)
void hash160(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), sha);
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, out);
}

// In‑place Base58Check
std::string base58Check(const std::vector<unsigned char>& data) {
    // copy + checksum
    std::vector<unsigned char> buf = data;
    unsigned char sha1[SHA256_DIGEST_LENGTH], sha2[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), sha1);
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    buf.insert(buf.end(), sha2, sha2+4);

    // count leading zeros
    size_t zeros = 0;
    while (zeros < buf.size() && buf[zeros]==0) ++zeros;

    // convert to base58
    std::vector<unsigned char> temp(buf.begin(), buf.end());
    std::string result;
    result.reserve(buf.size()*138/100 + 1);
    size_t start = zeros;
    while (start < temp.size()) {
        int carry = 0;
        for (size_t i = start; i < temp.size(); ++i) {
            int val = (carry << 8) + temp[i];
            temp[i] = val / 58;
            carry = val % 58;
        }
        result.push_back(BASE58_ALPHABET[carry]);
        while (start < temp.size() && temp[start]==0) ++start;
    }
    // leading '1's
    for (size_t i = 0; i < zeros; ++i) result.push_back('1');
    std::reverse(result.begin(), result.end());
    return result;
}

// Given priv[32], derive both uncompressed & compressed addresses and check
void derive_and_check(
    const std::vector<unsigned char>& priv,
    secp256k1_context* ctx,
    const std::unordered_set<std::string>& funded,
    std::ofstream& out)
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv.data())) return;

    unsigned char buf1[65]; size_t l1 = 65;
    secp256k1_ec_pubkey_serialize(ctx, buf1, &l1, &pub, SECP256K1_EC_UNCOMPRESSED);
    std::vector<unsigned char> v1(buf1, buf1+l1);
    unsigned char h160[20];
    hash160(v1, h160);
    std::vector<unsigned char> a1 = {0x00};
    a1.insert(a1.end(), h160, h160+20);
    auto addr1 = base58Check(a1);

    unsigned char buf2[33]; size_t l2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, buf2, &l2, &pub, SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> v2(buf2, buf2+l2);
    hash160(v2, h160);
    std::vector<unsigned char> a2 = {0x00};
    a2.insert(a2.end(), h160, h160+20);
    auto addr2 = base58Check(a2);

    std::lock_guard<std::mutex> g(file_mutex);
    if (funded.count(addr1)) {
        out << addr1 << " PRIV:";
        for (auto c:priv) out << std::hex << (int)c;
        out << "\n";
    }
    if (funded.count(addr2)) {
        out << addr2 << " PRIV:";
        for (auto c:priv) out << std::hex << (int)c;
        out << "\n";
    }
}

// Worker thread
void worker(const std::unordered_set<std::string>& funded) {
    XorShift64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id()) ^ std::random_device{}());
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::ofstream out("address.txt", std::ios::app);

    std::vector<unsigned char> priv(32);
    uint64_t local_count = 0;

    while (true) {
        // generate 32 random bytes
        for (int i = 0; i < 4; ++i) {
            uint64_t r = rng.next();
            for (int b = 0; b < 8; ++b) priv[i*8 + b] = (r >> (8*b)) & 0xFF;
        }
        derive_and_check(priv, ctx, funded, out);

        if (++local_count >= 1024) {
            total_checked.fetch_add(local_count, std::memory_order_relaxed);
            local_count = 0;
        }
    }
}

int main(int argc, char** argv) {
    std::string path = (argc > 1)
        ? argv[1]
        : "/mnt/c/Users/jjmor/Downloads/bitcoin_addresses_latest.tsv";

    auto funded = loadFunded(path);
    std::cout << "[+] Loaded funded addresses: " << funded.size() << "\n";
    if (funded.empty()) {
        std::cerr << "No addresses loaded – check your file path & format.\n";
        return 1;
    }

    // Progress reporter
    std::thread reporter([&](){
        uint64_t prev = 0;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t now = total_checked.load();
            std::cout << "[*] Checked " << now
                      << " keys (+" << (now - prev) << "/s)\n";
            prev = now;
        }
    });

    // Launch worker threads
    unsigned int threads_n = std::max(1u, std::thread::hardware_concurrency() - 1);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < threads_n; ++i)
        threads.emplace_back(worker, std::cref(funded));

    reporter.detach();
    for (auto& t : threads) t.join();
    return 0;
}
