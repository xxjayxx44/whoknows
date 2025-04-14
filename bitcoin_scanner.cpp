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
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }
};

// Atomic counters and synchronization
std::atomic<uint64_t> total_checked{0};
std::mutex file_mutex;

// Load funded addresses into a hash set
std::unordered_set<std::string> loadFunded(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    std::unordered_set<std::string> s;
    s.reserve(5'000'000); // adjust to your dataset size
    while (std::getline(in, line)) {
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (!line.empty()) s.insert(line);
    }
    return s;
}

// SHA256 then RIPEMD160
void hash160(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), sha);
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, out);
}

// In-place Base58Check encoder
std::string base58Check(const std::vector<unsigned char>& data) {
    // 1) append 4-byte checksum
    std::vector<unsigned char> buf(data);
    unsigned char sha1[SHA256_DIGEST_LENGTH], sha2[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), sha1);
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    buf.insert(buf.end(), sha2, sha2+4);

    // 2) count leading zeros
    size_t zeros = 0;
    while (zeros < buf.size() && buf[zeros]==0) ++zeros;

    // 3) convert to base58 digits
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
        while (start<temp.size() && temp[start]==0) ++start;
    }
    // 4) leading zeros
    for (size_t i=0; i<zeros; ++i) result.push_back('1');
    // 5) reverse
    std::reverse(result.begin(), result.end());
    return result;
}

// Derive compressed and uncompressed addresses
void derive_and_check(const std::vector<unsigned char>& priv,
                      secp256k1_context* ctx,
                      const std::unordered_set<std::string>& funded,
                      std::ofstream& out) {
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv.data())) return;

    // serialize uncompressed
    unsigned char uncmp[65]; size_t l1=65;
    secp256k1_ec_pubkey_serialize(ctx, uncmp, &l1, &pub, SECP256K1_EC_UNCOMPRESSED);
    std::vector<unsigned char> u1(uncmp, uncmp+l1);
    unsigned char h160[20];
    hash160(u1, h160);
    std::vector<unsigned char> addr1 = {0x00};
    addr1.insert(addr1.end(), h160, h160+20);
    auto a1 = base58Check(addr1);

    // compressed
    unsigned char cmp[33]; size_t l2=33;
    secp256k1_ec_pubkey_serialize(ctx, cmp, &l2, &pub, SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> u2(cmp, cmp+l2);
    hash160(u2, h160);
    std::vector<unsigned char> addr2 = {0x00};
    addr2.insert(addr2.end(), h160, h160+20);
    auto a2 = base58Check(addr2);

    // check
    if (funded.count(a1)) {
        std::lock_guard<std::mutex> g(file_mutex);
        out << a1 << " PRIV:"; 
        for (auto c:priv) out << std::hex << (int)(unsigned char)c;
        out << "\n";
    }
    if (funded.count(a2)) {
        std::lock_guard<std::mutex> g(file_mutex);
        out << a2 << " PRIV:"; 
        for (auto c:priv) out << std::hex << (int)(unsigned char)c;
        out << "\n";
    }
}

// Worker thread function
void worker(const std::unordered_set<std::string>& funded) {
    // each thread gets its own RNG
    XorShift64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id()) ^ std::random_device{}());
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::ofstream out("address.txt", std::ios::app);

    std::vector<unsigned char> priv(32);
    uint64_t local_count = 0;

    while (true) {
        // generate 32 random bytes
        for (int i = 0; i < 4; ++i) {
            uint64_t r = rng.next();
            for (int b = 0; b < 8; ++b)
                priv[i*8 + b] = (r >> (8*b)) & 0xFF;
        }
        derive_and_check(priv, ctx, funded, out);

        if (++local_count >= 1024) {
            total_checked.fetch_add(local_count, std::memory_order_relaxed);
            local_count = 0;
        }
    }
}

int main() {
    auto funded = loadFunded("/mnt/c/Users/jjmor/Downloads/bitcoin_addresses_latest.tsv");
    std::cout << "[+] Loaded funded addresses: " << funded.size() << "\n";

    // start progress reporter
    std::thread reporter([](){
        uint64_t prev = 0;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t now = total_checked.load();
            std::cout << "[*] Checked " << now
                      << " keys (+" << (now - prev) << "/s)\n";
            prev = now;
        }
    });

    // start worker threads
    unsigned int n = std::max(1u, std::thread::hardware_concurrency() - 1);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < n; ++i)
        threads.emplace_back(worker, std::cref(funded));

    reporter.detach();
    for (auto& t : threads) t.join();
    return 0;
}
