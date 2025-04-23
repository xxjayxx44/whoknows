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
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

namespace fs = std::filesystem;

// Custom hash for array<uchar,20>
namespace std {
  template<> struct hash<array<unsigned char,20>> {
    size_t operator()(array<unsigned char,20> const& a) const noexcept {
      uint64_t h = 146527;
      for (auto c : a) { h ^= c; h *= 1099511628211ull; }
      return size_t(h);
    }
  };
}

static const char* BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

constexpr size_t MAX_FUNDED_ADDRESSES = 100000;

static std::atomic<uint64_t> total_checked{0};
static std::atomic<uint64_t> funded_loaded{0};
static std::atomic<bool> found{false};
static std::mutex file_mutex;

// Fast xorshift RNG
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

// Inline Base58 decode (to little endian)
bool base58Decode(const std::string& str, std::vector<unsigned char>& out) {
  out.clear();
  std::vector<unsigned char> b256; b256.reserve(str.size());
  for (char c : str) {
    const char* p = std::strchr(BASE58_ALPHABET, c);
    if (!p) return false;
    int digit = int(p - BASE58_ALPHABET), carry = digit;
    for (size_t i = 0; i < b256.size(); ++i) {
      carry += b256[i] * 58;
      b256[i] = carry & 0xFF;
      carry >>= 8;
    }
    while (carry) {
      b256.push_back(carry & 0xFF);
      carry >>= 8;
    }
  }
  size_t zeros = 0;
  for (char c : str) {
    if (c == '1') zeros++;
    else break;
  }
  out.assign(zeros, 0x00);
  for (auto it = b256.rbegin(); it != b256.rend(); ++it)
    out.push_back(*it);
  return true;
}

// Base58Check decode to 20-byte payload
bool decodeBase58Check(const std::string& str, std::array<unsigned char,20>& out) {
  std::vector<unsigned char> full;
  if (!base58Decode(str, full) || full.size() < 5) return false;
  size_t plen = full.size() - 5;
  if (plen != 20) return false;
  unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
  SHA256(full.data(), 1 + plen, h1);
  SHA256(h1, SHA256_DIGEST_LENGTH, h2);
  if (std::memcmp(h2, full.data() + 1 + plen, 4) != 0) return false;
  std::memcpy(out.data(), full.data() + 1, 20);
  return true;
}

// Reservoir-sample up to MAX_FUNDED_ADDRESSES decoded hash160s
std::unordered_set<std::array<unsigned char,20>> loadFunded(const std::string& path) {
  std::vector<std::array<unsigned char,20>> reservoir;
  reservoir.reserve(MAX_FUNDED_ADDRESSES);
  size_t seen = 0;
  std::mt19937_64 rng(std::random_device{}());

  auto process = [&](const std::string& line){
    std::array<unsigned char,20> h;
    if (!decodeBase58Check(line, h)) return;
    if (seen < MAX_FUNDED_ADDRESSES) {
      reservoir.push_back(h);
    } else {
      std::uniform_int_distribution<size_t> dist(0, seen);
      size_t j = dist(rng);
      if (j < MAX_FUNDED_ADDRESSES) reservoir[j] = h;
    }
    ++seen;
  };

  if (path.size() > 3 && path.substr(path.size()-3) == ".gz") {
    gzFile gz = gzopen(path.c_str(), "rb");
    if (!gz) { std::cerr << "Cannot open " << path << "\n"; std::exit(1); }
    char buf[1<<20];
    while (gzgets(gz, buf, sizeof(buf))) {
      std::string s(buf);
      s.erase(std::remove_if(s.begin(), s.end(), [](char c){ return c=='\r'||c=='\n'; }), s.end());
      if (s.empty()) continue;
      if (auto t = s.find('\t'); t != std::string::npos) s.resize(t);
      process(s);
    }
    gzclose(gz);
  } else {
    std::ifstream in(path);
    if (!in) { std::cerr << "Cannot open " << path << "\n"; std::exit(1); }
    std::string s;
    while (std::getline(in, s)) {
      s.erase(std::remove_if(s.begin(), s.end(), [](char c){ return c=='\r'||c=='\n'; }), s.end());
      if (s.empty()) continue;
      if (auto t = s.find('\t'); t != std::string::npos) s.resize(t);
      process(s);
    }
  }

  std::unordered_set<std::array<unsigned char,20>> set;
  set.reserve(reservoir.size());
  for (auto &h : reservoir) set.insert(h);
  funded_loaded.store(set.size(), std::memory_order_relaxed);
  return set;
}

// Fast SHA256→RIPEMD160
inline void hash160(const unsigned char* data, size_t len, unsigned char out[20]) {
  unsigned char sha[SHA256_DIGEST_LENGTH];
  SHA256(data, len, sha);
  RIPEMD160(sha, SHA256_DIGEST_LENGTH, out);
}

// Base58Check encode from raw byte buffer
std::string base58Check(const unsigned char* data, size_t len) {
  std::vector<unsigned char> buf(data, data+len);
  unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
  SHA256(buf.data(), buf.size(), h1);
  SHA256(h1, SHA256_DIGEST_LENGTH, h2);
  buf.insert(buf.end(), h2, h2+4);

  size_t zeros = 0;
  while (zeros < buf.size() && buf[zeros] == 0) ++zeros;

  std::vector<unsigned char> tmp(buf.begin(), buf.end());
  std::string res; res.reserve(buf.size()*138/100 + 1);
  size_t start = zeros;
  while (start < tmp.size()) {
    int carry = 0;
    for (size_t i = start; i < tmp.size(); ++i) {
      int v = (carry << 8) + tmp[i];
      tmp[i] = v / 58;
      carry = v % 58;
    }
    res.push_back(BASE58_ALPHABET[carry]);
    while (start < tmp.size() && tmp[start] == 0) ++start;
  }
  for (size_t i = 0; i < zeros; ++i) res.push_back('1');
  std::reverse(res.begin(), res.end());
  return res;
}

// Derive compressed pubkey, match, and on hit log hex64+WIF+address
void derive_and_check(
  const unsigned char* priv,
  secp256k1_context* ctx,
  const std::unordered_set<std::array<unsigned char,20>>& funded,
  std::ofstream& out)
{
  if (found.load()) return;
  secp256k1_pubkey pub;
  if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) return;

  unsigned char pubc[33]; size_t plen=33;
  secp256k1_ec_pubkey_serialize(ctx, pubc, &plen, &pub, SECP256K1_EC_COMPRESSED);

  unsigned char h160[20];
  hash160(pubc, plen, h160);

  std::array<unsigned char,20> key;
  std::memcpy(key.data(), h160, 20);

  if (funded.count(key)) {
    // PRIV_HEX
    char hexbuf[65];
    static const char* hexmap="0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
      hexbuf[2*i]   = hexmap[(priv[i] >> 4) & 0xF];
      hexbuf[2*i+1] = hexmap[priv[i] & 0xF];
    }
    hexbuf[64]='\0';

    // WIF: prefix 0x80 + priv + 0x01
    unsigned char wifd[34];
    wifd[0]=0x80; std::memcpy(wifd+1, priv, 32); wifd[33]=0x01;
    std::string wif = base58Check(wifd, 34);

    // address: prefix 0x00 + h160
    unsigned char adr[21];
    adr[0]=0x00; std::memcpy(adr+1, h160, 20);
    std::string addr = base58Check(adr, 21);

    {
      std::lock_guard<std::mutex> g(file_mutex);
      out << addr
          << " PRIV_HEX:" << hexbuf
          << " WIF:" << wif
          << "\n";
    }
    found.store(true);
  }
}

// Worker thread
void worker(const std::unordered_set<std::array<unsigned char,20>>& funded) {
  XorShift64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id())
                 ^ std::random_device{}());
  auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  std::ofstream out("addresses.txt", std::ios::app);
  unsigned char priv[32];
  uint64_t local=0;

  while (!found.load()) {
    // fill 32 bytes
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
  std::vector<std::string> cands;
  if (argc > 1) cands.push_back(argv[1]);
  cands.push_back(fname);
  cands.push_back(fname + ".gz");
  cands.push_back("/mnt/c/Users/jjmor/Downloads/" + fname);
  cands.push_back("/mnt/c/Users/jjmor/Downloads/" + fname + ".gz");
  if (auto*h = std::getenv("HOME")) {
    cands.push_back(std::string(h)+"/"+fname);
    cands.push_back(std::string(h)+"/"+fname+".gz");
  }

  std::string path;
  for (auto& p : cands) {
    if (fs::exists(p) && fs::is_regular_file(p)) { path = p; break; }
  }
  if (path.empty()) {
    std::cerr << "Error: cannot find " << fname << "\n";
    return 1;
  }

  std::cout << "[*] Sampling up to " << MAX_FUNDED_ADDRESSES << " funded addresses...\n";
  auto funded = loadFunded(path);
  std::cout << "[+] Loaded " << funded_loaded.load() << " funded addresses.\n";
  if (funded.empty()) {
    std::cerr << "No addresses loaded—check file format.\n";
    return 1;
  }

  // Progress reporter
  std::thread rep([&](){
    uint64_t prev = 0;
    while (!found.load()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      uint64_t now = total_checked.load();
      std::cout << "[*] Checked " << now << " keys (+" << (now - prev) << "/s)\n";
      prev = now;
    }
  });
  rep.detach();

  // Launch workers
  unsigned int n = std::max(1u, std::thread::hardware_concurrency() - 1);
  std::vector<std::thread> threads;
  for (unsigned i = 0; i < n; ++i)
    threads.emplace_back(worker, std::cref(funded));
  for (auto& t : threads) t.join();

  std::cout << "[!] Match found—exiting.\n";
  return 0;
}
