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

using namespace std;
namespace fs = std::filesystem;

// Custom hash for 20‐byte arrays
namespace std {
  template<> struct hash<array<unsigned char,20>> {
    size_t operator()(array<unsigned char,20> const& a) const noexcept {
      uint64_t h = 146527;
      for (auto c : a) { h ^= c; h *= 1099511628211ULL; }
      return size_t(h);
    }
  };
}

// Base58 alphabet
static const char* BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// How many funded to sample
constexpr size_t MAX_FUNDED = 100000;

// Shared state
static atomic<uint64_t> total_checked{0};
static atomic<uint64_t> funded_loaded{0};
static atomic<bool> found{false};
static mutex file_mutex;

// Fast RNG
struct XorShift64 {
  uint64_t s;
  XorShift64(uint64_t seed=0xdeadbeefcafebabeULL):s(seed){}
  inline uint64_t next(){
    uint64_t x=s; x^=x>>12; x^=x<<25; x^=x>>27; return s=x*0x2545F4914F6CDD1DULL;
  }
};

// Decode Base58 → little-endian bytes
static bool base58Decode(const string& str, vector<unsigned char>& out){
  out.clear();
  vector<unsigned char> buf; buf.reserve(str.size());
  for(char c:str){
    const char* p=strchr(BASE58_ALPHABET,c);
    if(!p) return false;
    int digit=int(p-BASE58_ALPHABET), carry=digit;
    for(size_t i=0;i<buf.size();++i){
      carry+=buf[i]*58;
      buf[i]=carry&0xFF; carry>>=8;
    }
    while(carry){ buf.push_back(carry&0xFF); carry>>=8; }
  }
  size_t zeros=0; for(char c:str){ if(c=='1') zeros++; else break; }
  out.assign(zeros,0);
  for(auto it=buf.rbegin(); it!=buf.rend(); ++it) out.push_back(*it);
  return true;
}

// Decode Base58Check → exactly 20-byte payload
static bool decodeBase58Check(const string& str, array<unsigned char,20>& out){
  vector<unsigned char> full;
  if(!base58Decode(str, full) || full.size()<5) return false;
  size_t plen = full.size()-5;
  if(plen!=20) return false;
  unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
  SHA256(full.data(), 1+plen, h1);
  SHA256(h1, SHA256_DIGEST_LENGTH, h2);
  if(memcmp(h2, full.data()+1+plen, 4)!=0) return false;
  memcpy(out.data(), full.data()+1, 20);
  return true;
}

// Reservoir‐sample up to MAX_FUNDED of decoded 20-byte hash160s
static unordered_set<array<unsigned char,20>> loadFunded(const string& path){
  vector<array<unsigned char,20>> R; R.reserve(MAX_FUNDED);
  size_t seen=0; mt19937_64 rng(random_device{}());
  auto proc = [&](const string& ln){
    array<unsigned char,20> h;
    if(!decodeBase58Check(ln,h)) return;
    if(seen<MAX_FUNDED) R.push_back(h);
    else {
      uniform_int_distribution<size_t> d(0,seen);
      size_t j=d(rng);
      if(j<MAX_FUNDED) R[j]=h;
    }
    ++seen;
  };

  if(path.size()>3 && path.substr(path.size()-3)==".gz"){
    gzFile gz=gzopen(path.c_str(),"rb");
    if(!gz){ cerr<<"Cannot open "<<path<<"\n"; exit(1); }
    char buf[1<<20];
    while(gzgets(gz,buf,sizeof(buf))){
      string s(buf);
      s.erase(remove_if(s.begin(),s.end(),[](char c){return c=='\r'||c=='\n';}),s.end());
      if(s.empty()) continue;
      if(auto t=s.find('\t'); t!=string::npos) s.resize(t);
      proc(s);
    }
    gzclose(gz);
  } else {
    ifstream in(path);
    if(!in){ cerr<<"Cannot open "<<path<<"\n"; exit(1); }
    string s;
    while(getline(in,s)){
      s.erase(remove_if(s.begin(),s.end(),[](char c){return c=='\r'||c=='\n';}),s.end());
      if(s.empty()) continue;
      if(auto t=s.find('\t'); t!=string::npos) s.resize(t);
      proc(s);
    }
  }

  unordered_set<array<unsigned char,20>> set;
  set.reserve(R.size());
  for(auto &h:R) set.insert(h);
  funded_loaded.store(set.size(), memory_order_relaxed);
  return set;
}

// SHA256→RIPEMD160
static inline void hash160(const unsigned char* d, size_t n, unsigned char o[20]){
  unsigned char sha[SHA256_DIGEST_LENGTH];
  SHA256(d,n,sha);
  RIPEMD160(sha,SHA256_DIGEST_LENGTH,o);
}

// Base58Check encode from raw buffer
static string base58Check(const unsigned char* data, size_t len){
  vector<unsigned char> buf(data,data+len);
  unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
  SHA256(buf.data(),buf.size(),h1);
  SHA256(h1,SHA256_DIGEST_LENGTH,h2);
  buf.insert(buf.end(),h2,h2+4);

  size_t zeros=0; while(zeros<buf.size()&&buf[zeros]==0) ++zeros;
  vector<unsigned char> tmp(buf.begin(),buf.end());
  string res; res.reserve(buf.size()*138/100+1);
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
  reverse(res.begin(),res.end());
  return res;
}

// Derive compressed pubkey, compare raw h160, log on hit
static void derive_and_check(
  const unsigned char priv[32],
  secp256k1_context* ctx,
  const unordered_set<array<unsigned char,20>>& funded,
  ofstream& out)
{
  if(found.load()) return;
  secp256k1_pubkey pub;
  if(!secp256k1_ec_pubkey_create(ctx,&pub,priv)) return;

  unsigned char pubc[33]; size_t plen=33;
  secp256k1_ec_pubkey_serialize(ctx,pubc,&plen,&pub,SECP256K1_EC_COMPRESSED);

  unsigned char h[20];
  hash160(pubc,plen,h);
  array<unsigned char,20> arr;
  memcpy(arr.data(),h,20);

  if(funded.count(arr)){
    // PRIV_HEX
    char hex64[65];
    static const char* hm="0123456789abcdef";
    for(int i=0;i<32;++i){
      hex64[2*i]   = hm[(priv[i]>>4)&0xF];
      hex64[2*i+1] = hm[priv[i]&0xF];
    }
    hex64[64]='\0';

    // WIF
    unsigned char wifd[34];
    wifd[0]=0x80;
    memcpy(wifd+1,priv,32);
    wifd[33]=0x01;
    string wif = base58Check(wifd,34);

    // Address
    unsigned char adr[21];
    adr[0]=0x00;
    memcpy(adr+1,h,20);
    string addr=base58Check(adr,21);

    {
      lock_guard<mutex> g(file_mutex);
      out<<addr
         <<" PRIV_HEX:"<<hex64
         <<" WIF:"<<wif<<"\n";
    }
    found.store(true);
  }
}

// Worker thread
static void worker(const unordered_set<array<unsigned char,20>>& funded){
  XorShift64 rng(hash<thread::id>()(this_thread::get_id()) ^ random_device{}());
  auto* ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  ofstream out("addresses.txt",ios::app);
  unsigned char priv[32];
  uint64_t local=0;

  while(!found.load()){
    for(int i=0;i<4;++i){
      uint64_t r=rng.next();
      for(int b=0;b<8;++b)
        priv[i*8+b]=(r>>(8*b))&0xFF;
    }
    derive_and_check(priv,ctx,funded,out);
    if(++local>=1024){
      total_checked.fetch_add(local,memory_order_relaxed);
      local=0;
    }
  }
}

int main(int argc,char**argv){
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  const string fname="bitcoin_addresses_latest.tsv";
  vector<string> cands;
  if(argc>1) cands.push_back(argv[1]);
  cands.push_back(fname);
  cands.push_back(fname+".gz");
  cands.push_back("/mnt/c/Users/jjmor/Downloads/"+fname);
  cands.push_back("/mnt/c/Users/jjmor/Downloads/"+fname+".gz");
  if(auto*h=getenv("HOME")){
    cands.push_back(string(h)+"/"+fname);
    cands.push_back(string(h)+"/"+fname+".gz");
  }

  string path;
  for(auto&p:cands)
    if(fs::exists(p)&&fs::is_regular_file(p)){ path=p; break; }
  if(path.empty()){
    cerr<<"Cannot find "<<fname<<"\n";
    return 1;
  }

  cout<<"[*] Sampling up to "<<MAX_FUNDED<<" funded addresses...\n";
  auto funded = loadFunded(path);
  cout<<"[+] Loaded "<<funded_loaded.load()<<" funded addresses.\n";
  if(funded.empty()){
    cerr<<"No addresses loaded—check format.\n";
    return 1;
  }

  // Progress reporter
  thread rep([&](){
    uint64_t prev=0;
    while(!found.load()){
      this_thread::sleep_for(chrono::seconds(1));
      uint64_t now=total_checked.load();
      cout<<"[*] Checked "<<now<<" keys (+"<<(now-prev)<<"/s)\n";
      prev=now;
    }
  });
  rep.detach();

  // Spawn one thread per hardware core
  unsigned int n=thread::hardware_concurrency();
  vector<thread> thr;
  thr.reserve(n);
  for(unsigned i=0;i<n;++i) thr.emplace_back(worker, funded);
  for(auto&t:thr) t.join();

  cout<<"[!] Hit found—exiting.\n";
  return 0;
}
