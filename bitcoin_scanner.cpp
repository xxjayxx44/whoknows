#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
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
#include <secp256k1.h>

namespace fs = std::filesystem;

// Base58 alphabet
static const char* BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// XorShift64* RNG for speed
struct XorShift64 {
    uint64_t state;
    XorShift64(uint64_t seed)
        : state(seed ? seed : 0xdeadbeefcafebabeULL) {}
    uint64_t next() {
        uint64_t x = state;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }
};

// Progress counter
std::atomic<uint64_t> total_checked{0};
std::atomic<uint64_t> funded_loaded{0};
std::mutex file_mutex;

// Load lines from a gzipped TSV
void loadLinesGz(const std::string& path, std::unordered_set<std::string>& s) {
    gzFile gz = gzopen(path.c_str(), "rb");
    if (!gz) {
        std::cerr << "Error: cannot open gz file: " << path << "\n";
        std::exit(1);
    }
    constexpr int BUF = 1<<20;
    char buf[BUF];
    while (gzgets(gz, buf, BUF)) {
        std::string line(buf);
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab!=std::string::npos) line.resize(tab);
        s.insert(line);
    }
    gzclose(gz);
}

// Load lines from a plain TSV
void loadLinesTxt(const std::string& path, std::unordered_set<std::string>& s) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "Error: cannot open file: " << path << "\n";
        std::exit(1);
    }
    std::string line;
    while (std::getline(in, line)) {
        line.erase(std::remove_if(line.begin(), line.end(),
            [](char c){ return c=='\r' || c=='\n'; }), line.end());
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab!=std::string::npos) line.resize(tab);
        s.insert(line);
    }
}

// Load funded addresses from TSV or TSV.GZ
std::unordered_set<std::string> loadFunded(const std::string& path) {
    std::unordered_set<std::string> s;
    s.reserve(5'000'000);
    if (path.size()>3 && path.substr(path.size()-3)==".gz") {
        loadLinesGz(path, s);
    } else {
        loadLinesTxt(path, s);
    }
    funded_loaded.store(s.size(), std::memory_order_relaxed);
    return s;
}

// SHA256 then RIPEMD160
void hash160(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), sha);
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, out);
}

// Base58Check (in‑place)
std::string base58Check(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> buf = data;
    unsigned char sha1[SHA256_DIGEST_LENGTH], sha2[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), sha1);
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    buf.insert(buf.end(), sha2, sha2+4);

    size_t zeros = 0;
    while (zeros<buf.size() && buf[zeros]==0) ++zeros;

    std::vector<unsigned char> temp(buf.begin(), buf.end());
    std::string result;
    result.reserve(buf.size()*138/100 + 1);
    size_t start = zeros;
    while (start < temp.size()) {
        int carry = 0;
        for (size_t i = start; i < temp.size(); ++i) {
            int val = (carry<<8) + temp[i];
            temp[i] = val/58;
            carry = val%58;
        }
        result.push_back(BASE58_ALPHABET[carry]);
        while (start<temp.size() && temp[start]==0) ++start;
    }
    for (size_t i=0;i<zeros;++i) result.push_back('1');
    std::reverse(result.begin(), result.end());
    return result;
}

// Derive both addresses, check against funded, log matches
void derive_and_check(
    const std::vector<unsigned char>& priv,
    secp256k1_context* ctx,
    const std::unordered_set<std::string>& funded,
    std::ofstream& out)
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv.data())) return;

    // uncompressed
    unsigned char buf1[65]; size_t l1=65;
    secp256k1_ec_pubkey_serialize(ctx, buf1, &l1, &pub, SECP256K1_EC_UNCOMPRESSED);
    std::vector<unsigned char> v1(buf1, buf1+l1);
    unsigned char h160[20];
    hash160(v1, h160);
    std::vector<unsigned char> a1={0x00};
    a1.insert(a1.end(), h160, h160+20);
    auto addr1 = base58Check(a1);

    // compressed
    unsigned char buf2[33]; size_t l2=33;
    secp256k1_ec_pubkey_serialize(ctx, buf2, &l2, &pub, SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> v2(buf2, buf2+l2);
    hash160(v2, h160);
    std::vector<unsigned char> a2={0x00};
    a2.insert(a2.end(), h160, h160+20);
    auto addr2 = base58Check(a2);

    std::lock_guard<std::mutex> g(file_mutex);
    if (funded.count(addr1)) {
        out<<addr1<<" PRIV:";
        for(auto c:priv) out<<std::hex<<(int)c;
        out<<"\n";
    }
    if (funded.count(addr2)) {
        out<<addr2<<" PRIV:";
        for(auto c:priv) out<<std::hex<<(int)c;
        out<<"\n";
    }
}

// Worker thread: generate keys, derive, check, count
void worker(const std::unordered_set<std::string>& funded) {
    XorShift64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id())
                   ^ std::random_device{}());
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::ofstream out("addresses.txt", std::ios::app);
    std::vector<unsigned char> priv(32);
    uint64_t local = 0;

    while (true) {
        for (int i=0;i<4;i++){
            uint64_t r = rng.next();
            for (int b=0;b<8;b++)
                priv[i*8+b] = (r>>(8*b)) & 0xFF;
        }
        derive_and_check(priv, ctx, funded, out);
        if (++local >= 1024) {
            total_checked.fetch_add(local, std::memory_order_relaxed);
            local = 0;
        }
    }
}

int main(int argc, char** argv) {
    const std::string fname = "bitcoin_addresses_latest.tsv";
    std::vector<std::string> candidates;

    // 1) cmd‑line
    if (argc>1) candidates.push_back(argv[1]);
    // 2) CWD
    candidates.push_back(fname);
    candidates.push_back(fname + ".gz");
    // 3) WSL Downloads
    candidates.push_back("/mnt/c/Users/jjmor/Downloads/" + fname);
    candidates.push_back("/mnt/c/Users/jjmor/Downloads/" + fname + ".gz");
    // 4) HOME
    if (const char* h = std::getenv("HOME")) {
        candidates.push_back(std::string(h)+"/"+fname);
        candidates.push_back(std::string(h)+"/"+fname+".gz");
    }

    std::string path;
    for (auto& p : candidates) {
        if (fs::exists(p) && fs::is_regular_file(p)) {
            path = p;
            break;
        }
    }
    if (path.empty()) {
        std::cerr<<"Error: could not find "<<fname<<"(.gz) in any expected location\n";
        return 1;
    }

    auto funded = loadFunded(path);
    std::cout<<"[+] Loaded funded addresses: "<<funded_loaded.load()<<"\n";
    if (funded.empty()) {
        std::cerr<<"No addresses loaded – check file format.\n
