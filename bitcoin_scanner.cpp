#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <random>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <algorithm>  // Include this for std::remove_if

// Base58 encoding
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58Encode(const std::string& input) {
    BIGNUM* bn = BN_new();
    BN_bin2bn((const unsigned char*)input.data(), input.size(), bn);
    BIGNUM* div = BN_new();
    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    std::string result;

    while (!BN_is_zero(bn)) {
        BN_div(div, rem, bn, BN_value_one(), ctx);  // divide by 58
        unsigned int index = BN_get_word(rem);
        result = BASE58_ALPHABET[index % 58] + result;
        BN_copy(bn, div);
    }

    for (unsigned char c : input) {
        if (c == 0x00) result = '1' + result;
        else break;
    }

    BN_free(bn);
    BN_free(div);
    BN_free(rem);
    BN_CTX_free(ctx);
    return result;
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.data(), input.size(), hash);
    return std::string((char*)hash, SHA256_DIGEST_LENGTH);
}

std::string ripemd160(const std::string& input) {
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160((const unsigned char*)input.data(), input.size(), hash);
    return std::string((char*)hash, RIPEMD160_DIGEST_LENGTH);
}

std::string publicKeyToAddress(const std::string& pubkey) {
    std::string sha = sha256(pubkey);
    std::string ripe = ripemd160(sha);
    std::string prefixed = '\x00' + ripe;
    std::string checksum = sha256(sha256(prefixed)).substr(0, 4);
    return base58Encode(prefixed + checksum);
}

std::string generatePrivateKey() {
    std::random_device rd;
    std::uniform_int_distribution<unsigned long long> dist(0, UINT64_MAX);
    std::string key(32, '\0');
    for (int i = 0; i < 32; i += 8) {
        uint64_t r = dist(rd);
        for (int j = 0; j < 8; ++j) {
            key[i + j] = static_cast<char>((r >> (8 * j)) & 0xff);
        }
    }
    return key;
}

std::string privateKeyToPublicKey(const std::string& privkey, secp256k1_context* ctx) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)privkey.data())) {
        return "";
    }
    unsigned char output[33];
    size_t outputLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, output, &outputLen, &pubkey, SECP256K1_EC_COMPRESSED);
    return std::string((char*)output, outputLen);
}

std::unordered_set<std::string> loadFundedAddresses(const std::string& filename) {
    std::unordered_set<std::string> addresses;
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), [](char c) {
            return c == '\r' || c == '\n';
        }), line.end());

        if (!line.empty()) {
            addresses.insert(line);
        }
    }
    return addresses;
}

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::unordered_set<std::string> funded = loadFundedAddresses("/mnt/c/Users/jjmor/Downloads/bitcoin_addresses_latest.tsv");
    std::ofstream outFile("address.txt", std::ios::app);
    int count = 0;

    while (true) {
        std::string privkey = generatePrivateKey();
        std::string pubkey = privateKeyToPublicKey(privkey, ctx);
        if (pubkey.empty()) continue;

        std::string address = publicKeyToAddress(pubkey);

        if (funded.find(address) != funded.end()) {
            std::cout << "[FOUND] " << address << std::endl;
            outFile << "Address: " << address << "\nPrivateKey (hex): ";
            for (unsigned char c : privkey)
                outFile << std::hex << (int)(unsigned char)c;
            outFile << "\n\n";
            outFile.flush();
        }

        if (++count % 1000 == 0) {
            std::cout << count << " keys checked...\n";
        }
    }

    secp256k1_context_destroy(ctx);
    return 0;
}
