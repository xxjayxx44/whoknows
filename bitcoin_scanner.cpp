#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <unordered_set>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

// === Config ===
#define FUNDED_PATH "/mnt/c/Users/jjmor/Downloads/bitcoin_addresses_latest.tsv.gz"
#define MAX_ADDRESSES 100000

std::mutex file_mutex;
std::atomic<uint64_t> total_keys(0);

// === Base58 Alphabet ===
const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// === Decode Base58Check to get the 20-byte hash160 ===
std::vector<uint8_t> decodeBase58Check(const std::string& addr) {
    BIGNUM* bn = BN_new();
    BN_zero(bn);
    BN_CTX* ctx = BN_CTX_new();

    for (char c : addr) {
        const char* p = strchr(BASE58, c);
        if (!p) return {};
        BN_mul_word(bn, 58);
        BN_add_word(bn, p - BASE58);
    }

    uint8_t tmp[40];
    int len = BN_num_bytes(bn);
    if (len > 40) return {};
    BN_bn2binpad(bn, tmp, 40);

    std::vector<uint8_t> raw(tmp + (40 - len), tmp + 40);
    BN_free(bn);
    BN_CTX_free(ctx);

    // Check size & checksum
    if (raw.size() < 25) return {};
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(raw.data(), raw.size() - 4, hash);
    SHA256(hash, SHA256_DIGEST_LENGTH, hash);

    if (memcmp(hash, raw.data() + raw.size() - 4, 4) != 0) return {};
    return std::vector<uint8_t>(raw.begin() + 1, raw.begin() + 21);
}

// === Load addresses ===
std::unordered_set<std::array<uint8_t, 20>> loadAddresses() {
    std::unordered_set<std::array<uint8_t, 20>> set;
    gzFile file = gzopen(FUNDED_PATH, "rb");
    if (!file) {
        std::cerr << "Failed to open address file.\n";
        exit(1);
    }

    char line[256];
    while (gzgets(file, line, sizeof(line)) && set.size() < MAX_ADDRESSES) {
        std::string str(line);
        auto tab = str.find('\t');
        if (tab != std::string::npos) str = str.substr(0, tab);

        auto hash = decodeBase58Check(str);
        if (hash.size() == 20) {
            std::array<uint8_t, 20> a;
            memcpy(a.data(), hash.data(), 20);
            set.insert(a);
        }
    }
    gzclose(file);
    std::cout << "[+] Loaded " << set.size() << " funded addresses\n";
    return set;
}

// === Hash160 ===
void hash160(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint8_t sha[32];
    SHA256(data, len, sha);
    RIPEMD160(sha, 32, out);
}

// === Compress pubkey ===
std::vector<uint8_t> getCompressedPubkey(secp256k1_context* ctx, const uint8_t priv[32]) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) return {};

    uint8_t output[33];
    size_t outlen = sizeof(output);
    secp256k1_ec_pubkey_serialize(ctx, output, &outlen, &pubkey, SECP256K1_EC_COMPRESSED);
    return std::vector<uint8_t>(output, output + outlen);
}

// === Base58Check (only for match logging) ===
std::string base58Encode(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> data = input;
    uint8_t hash[32];
    SHA256(data.data(), data.size(), hash);
    SHA256(hash, 32, hash);
    data.insert(data.end(), hash, hash + 4);

    BIGNUM* bn = BN_new();
    BN_bin2bn(data.data(), data.size(), bn);
    char buf[100];
    char* out = buf + sizeof(buf);
    *--out = '\0';

    BIGNUM* div = BN_new();
    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* base = BN_new();
    BN_set_word(base, 58);

    while (!BN_is_zero(bn)) {
        BN_div(div, rem, bn, base, ctx);
        int rem_int = BN_get_word(rem);
        *--out = BASE58[rem_int];
        BN_copy(bn, div);
    }

    for (uint8_t c : input) {
        if (c == 0x00) *--out = '1';
        else break;
    }

    std::string result(out);
    BN_free(bn); BN_free(div); BN_free(rem); BN_free(base); BN_CTX_free(ctx);
    return result;
}

// === Thread Worker ===
void scanner(const std::unordered_set<std::array<uint8_t, 20>>& funded) {
    auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::ofstream fout("address.txt", std::ios::app);

    while (true) {
        uint8_t priv[32];
        for (int i = 0; i < 4; i++) {
            uint64_t r = dis(gen);
            memcpy(priv + i * 8, &r, 8);
        }

        auto pub = getCompressedPubkey(ctx, priv);
        if (pub.empty()) continue;

        uint8_t h160[20];
        hash160(pub.data(), pub.size(), h160);

        std::array<uint8_t, 20> key;
        memcpy(key.data(), h160, 20);

        if (funded.find(key) != funded.end()) {
            std::lock_guard<std::mutex> lock(file_mutex);

            std::vector<uint8_t> data = {0x00};
            data.insert(data.end(), h160, h160 + 20);

            fout << "[MATCH] Address: " << base58Encode(data) << " Priv: ";
            for (int i = 0; i < 32; i++)
                fout << std::hex << (priv[i] >> 4) << (priv[i] & 0x0F);
            fout << std::endl;
        }

        total_keys++;
    }
}

int main() {
    auto funded = loadAddresses();
    unsigned threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 2;

    std::cout << "[*] Launching " << threads << " threads...\n";

    for (unsigned i = 0; i < threads; ++i)
        std::thread(scanner, std::cref(funded)).detach();

    while (true) {
        auto now = total_keys.load();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto after = total_keys.load();
        std::cout << "[*] " << after << " keys checked (" << (after - now) << "/s)\n";
    }
}
