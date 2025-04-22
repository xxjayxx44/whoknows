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
#include <vector>

#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

namespace fs = std::filesystem;

static const char* BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

constexpr size_t MAX_FUNDED_ADDRESSES = 100000;

static std::atomic<uint64_t> total_checked{0};
static std::atomic<uint64_t> funded_loaded{0};
static std::atomic<bool> found{false};
static std::mutex file_mutex;

struct SplitMix64 {
  uint64_t state;
  SplitMix64(uint64_t seed) : state(seed) {}
  inline uint64_t next() {
    uint64_t z = (state += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
  }
};

// decode Base58 → little-endian byte vector
bool base58Decode(const std::string& str, std::vector<unsigned char>& out) {
  std::vector<unsigned char> b256; b256.reserve(str.size());
  for(char c:str){
    const char* p = std::strchr(BASE58_ALPHABET,c);
    if(!p) return false;
    int digit = p - BASE58_ALPHABET, carry=digit;
    for(size_t i=0;i<b256.size();++i){
      carry += b256[i]*58;
      b256[i] = carry & 0xFF;
      carry >>= 8;
    }
    while(carry){ b256.push_back(carry&0xFF); carry>>=8; }
  }
  size_t zeros=0;
  for(char c:str){ if(c=='1') zeros++; else break; }
  out.assign(zeros,0x00);
  for(auto it=b256.rbegin();it!=b256.rend();++it) out.push_back(*it);
  return true;
}

// Base58Check decode → payload (20 bytes)
bool decodeBase58Check(const std::string& str, std::array<unsigned char,20>& out) {
  std::vector<unsigned char> full;
  if(!base58Decode(str, full) || full.size()<5) return false;
  size_t plen = full.size()-5;
  if(plen!=20) return false;
  unsigned char hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
  SHA256(full.data(),1+plen,hash1);
  SHA256(hash1,SHA256_DIGEST_LENGTH,hash2);
  if(std::memcmp(hash2, full.data()+1+plen,4)!=0) return false;
  std::memcpy(out.data(), full.data()+1,20);
  return true;
}

// Reservoir sample directly into array<uchar,20>
std::vector<std::array<unsigned char,20>> loadFunded(const std::string& path) {
  std::vector<std::array<unsigned char,20>> reservoir;
  reservoir.reserve(MAX_FUNDED_ADDRESSES);
  size_t seen=0;
  std::mt19937_64 rng(std::random_device{}());

  auto processLine = [&](const std::string& line){
    std::array<unsigned char,20> h;
    if(!decodeBase58Check(line,h)) return;
    if(seen<MAX_FUNDED_ADDRESSES) {
      reservoir.push_back(h);
    } else {
      std::uniform_int_distribution<size_t> dist(0,seen);
      size_t j = dist(rng);
      if(j<MAX_FUNDED_ADDRESSES) reservoir[j]=h;
    }
    ++seen;
  };

  if(path.size()>3 && path.substr(path.size()-3)==".gz") {
    gzFile gz = gzopen(path.c_str(),"rb");
    if(!gz){ std::cerr<<"Cannot open "<<path<<"\n"; std::exit(1); }
    constexpr int BUF=1<<20; char buf[BUF];
    while(gzgets(gz,buf,BUF)){
      std::string s(buf);
      s.erase(std::remove_if(s.begin(),s.end(),[](char c){return c=='\r'||c=='\n';}),s.end());
      if(s.empty()) continue;
      if(auto t=s.find('\t'); t!=std::string::npos) s.resize(t);
      processLine(s);
    }
    gzclose(gz);
  } else {
    std::ifstream in(path);
    if(!in){ std::cerr<<"Cannot open "<<path<<"\n"; std::exit(1); }
    std::string s;
    while(std::getline(in,s)) {
      s.erase(std::remove_if(s.begin(),s.end(),[](char c){return c=='\r'||c=='\n';}),s.end());
      if(s.empty()) continue;
      if(auto t=s.find('\t'); t!=std::string::npos) s.resize(t);
      processLine(s);
    }
  }

  std::sort(reservoir.begin(), reservoir.end());
  funded_loaded.store(reservoir.size(), std::memory_order_relaxed);
  return reservoir;
}

// hash160 = RIPEMD160(SHA256(data))
inline void hash160(const unsigned char* d, size_t n, unsigned char out[20]) {
  unsigned char sha[SHA256_DIGEST_LENGTH];
  SHA256(d,n,sha);
  RIPEMD160(sha,SHA256_DIGEST_LENGTH,out);
}

// Base58Check encode
std::string base58Check(const std::vector<unsigned char>& data) {
  std::vector<unsigned char> buf(data);
  unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
  SHA256(buf.data(),buf.size(),h1);
  SHA256(h1,SHA256_DIGEST_LENGTH,h2);
  buf.insert(buf.end(),h2,h2+4);

  size_t zeros=0; while(zeros<buf.size()&&buf[zeros]==0) ++zeros;
  std::vector<unsigned char> tmp(buf.begin(),buf.end());
  std::string res; res.reserve(buf.size()*138/100+1);
  size_t start=zeros;
  while(start<tmp.size()){
    int carry=0;
    for(size_t i=start;i<tmp.size();++i){
      int v=(carry<<8)+tmp[i];
      tmp[i]=v/58; carry=v%58;
    }
    res.push_back(BASE58_ALPHABET[carry]);
    while(start<tmp.size()&&tmp[start]==0) ++start;
  }
  for(size_t i=0;i<zeros;++i) res.push_back('1');
  std::reverse(res.begin(),res.end());
  return res;
}

// derive compressed pubkey, match raw h160, log hex+WIF
void derive_and_check(
  const std::array<unsigned char,32>& priv,
  secp256k1_context* ctx,
  const std::vector<std::array<unsigned char,20>>& funded,
  std::ofstream& out)
{
  if(found.load(std::memory_order_relaxed)) return;

  secp256k1_pubkey pub;
  if(!secp256k1_ec_pubkey_create(ctx,&pub,priv.data())) return;

  unsigned char buf[33]; size_t len=33;
  secp256k1_ec_pubkey_serialize(ctx,buf,&len,&pub,SECP256K1_EC_COMPRESSED);

  unsigned char h[20];
  hash160(buf,len,h);
  std::array<unsigned char,20> a;
  std::memcpy(a.data(),h,20);

  if(std::binary_search(funded.begin(), funded.end(), a)){
    // PRIV_HEX
    std::ostringstream hs;
    hs<<std::hex<<std::setfill('0');
    for(auto c:priv) hs<<std::setw(2)<<(int)c;
    std::string hex64=hs.str();

    // WIF
    std::vector<unsigned char> wifd; wifd.reserve(34+5);
    wifd.push_back(0x80);
    wifd.insert(wifd.end(),priv.begin(),priv.end());
    wifd.push_back(0x01);
    std::string wif=base58Check(wifd);

    // Address
    std::vector<unsigned char> adr; adr.reserve(21);
    adr.push_back(0x00);
    adr.insert(adr.end(),h,h+20);
    std::string addr=base58Check(adr);

    {
      std::lock_guard<std::mutex> g(file_mutex);
      out<<addr
         <<" PRIV_HEX:"<<hex64
         <<" WIF:"<<wif<<"\n";
    }
    found.store(true, std::memory_order_relaxed);
  }
}

// worker thread
void worker(const std::vector<std::array<unsigned char,20>>& funded){
  SplitMix64 rng(std::hash<std::thread::id>{}(std::this_thread::get_id())
                 ^ std::random_device{}());
  auto* ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  std::ofstream out("addresses.txt",std::ios::app);
  std::array<unsigned char,32> priv;
  uint64_t local=0;

  while(!found.load(std::memory_order_relaxed)){
    uint64_t r[4];
    r[0] = rng.next();
    r[1] = rng.next();
    r[2] = rng.next();
    r[3] = rng.next();
    std::memcpy(priv.data(), r, 32);
    derive_and_check(priv,ctx,funded,out);
    if(++local>=1024){
      total_checked.fetch_add(local,std::memory_order_relaxed);
      local=0;
    }
  }
}

int main(int argc,char**argv){
  std::ios::sync_with_stdio(false);
  std::cin.tie(nullptr);

  const std::string fname="bitcoin_addresses_latest.tsv";
  std::vector<std::string> cands;
  if(argc>1) cands.push_back(argv[1]);
  cands.push_back(fname);
  cands.push_back(fname+".gz");
  cands.push_back("/mnt/c/Users/jjmor/Downloads/"+fname);
  cands.push_back("/mnt/c/Users/jjmor/Downloads/"+fname+".gz");
  if(auto*h=getenv("HOME")){
    cands.push_back(std::string(h)+"/"+fname);
    cands.push_back(std::string(h)+"/"+fname+".gz");
  }

  std::string path;
  for(auto&p:cands)
    if(fs::exists(p)&&fs::is_regular_file(p)){ path=p; break; }
  if(path.empty()){
    std::cerr<<"Cannot find "<<fname<<"(.gz)\n";
    return 1;
  }

  std::cout<<"[*] Sampling up to "<<MAX_FUNDED_ADDRESSES<<" funded addresses...\n";
  auto funded = loadFunded(path);
  std::cout<<"[+] Loaded "<<funded_loaded.load()<<" funded addresses.\n";
  if(funded.empty()){
    std::cerr<<"No addresses loaded—check file format.\n";
    return 1;
  }

  // progress reporter
  std::thread rep([&](){
    uint64_t prev=0;
    while(!found.load(std::memory_order_relaxed)){
      std::this_thread::sleep_for(std::chrono::seconds(1));
      uint64_t now=total_checked.load();
      std::cout<<"[*] Checked "<<now<<" keys (+"<<(now-prev)<<"/s)\n";
      prev=now;
    }
  });
  rep.detach();

  unsigned int n=std::max(1u,std::thread::hardware_concurrency());
  std::vector<std::thread> threads;
  for(unsigned i=0;i<n;++i)
    threads.emplace_back(worker,std::cref(funded));
  for(auto& t:threads) t.join();

  std::cout<<"[!] Hit found, exiting.\n";
  return 0;
}
