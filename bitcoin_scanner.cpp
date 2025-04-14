#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_ecdh.h>

// Base58 Alphabet
const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Load funded addresses from file into an unordered_set
std::unordered_set<std::string> loadFundedAddresses(const std::string& filename) {
    std::unordered_set<std::string> addresses;
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
        if (!line.empty()) {
            addresses.insert(line);
        }
    }
    return addresses;
}

// Convert hex string to binary
std::vector<unsigned char> hexStrToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// SHA256
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// RIPEMD160
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), hash.data());
    return hash;
}

// Base58Check Encoding
std::string base58checkEncode(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> full(data);
    std::vector<unsigned char> hash = sha256(sha256(data));
    full.insert(full.end(), hash.begin(), hash.begin() + 4); // 4-byte checksum

    // Convert to base58
    BIGNUM* bn = BN_new();
    BN_bin2bn(full.data(), full.size(), bn);

    BIGNUM* div = BN_new();
    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    std::string result;

    while (!BN_is_zero(bn)) {
        BN_div(div, rem, bn, BN_value_one(), ctx);
        int index = BN_get_word(rem) % 58;
        result = BASE58_ALPHABET[index] + result;
        BN_copy(bn, div);
    }

    // Add leading 1s for leading 0 bytes
    for (size_t i = 0; i < full.size() && full[i] == 0; ++i) {
        result = '1' + result;
    }

    BN_free(bn);
    BN_free(div);
    BN_free(rem);
    BN_CTX_free(ctx);
    return result;
}

// Generate a random 32-byte private key
std::vector<unsigned char> generatePrivateKey() {
    std::vector<unsigned char> privKey(32);
    std::random_device rd;
    std::mt19937_64 rng(rd());
    for (int i = 0; i < 32; ++i) {
        privKey[i] = rng() & 0xFF;
    }
    return privKey;
}

// Derive both compressed and uncompressed Bitcoin addresses
std::vector<std::string> deriveAddresses(const std::vector<unsigned char>& privKey, secp256k1_context* ctx) {
    std::vector<std::string> result;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data())) return result;

    // Uncompressed
    unsigned char uncompressed[65];
    size_t len1 = 65;
    secp256k1_ec_pubkey_serialize(ctx, uncompressed, &len1, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    std::vector<unsigned char> pubBytes1(uncompressed, uncompressed + len1);
    std::vector<unsigned char> hash160_1 = ripemd160(sha256(pubBytes1));
    std::vector<unsigned char> address1 = {0x00}; // Mainnet prefix
    address1.insert(address1.end(), hash160_1.begin(), hash160_1.end());
    result.push_back(base58checkEncode(address1));

    // Compressed
    unsigned char compressed[33];
    size_t len2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, compressed, &len2, &pubkey, SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> pubBytes2(compressed, compressed + len2);
    std::vector<unsigned char> hash160_2 = ripemd160(sha256(pubBytes2));
    std::vector<unsigned char> address2 = {0x00};
    address2.insert(address2.end(), hash160_2.begin(), hash160_2.end());
    result.push_back(base58checkEncode(address2));

    return result;
}

std::string toHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    for (auto byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

int main() {
    std::string fundedPath = "/mnt/c/Users/jjmor/Downloads/bitcoin_addresses_latest.tsv";

    std::cout << "[*] Loading funded addresses...\n";
    auto fundedAddresses = loadFundedAddresses(fundedPath);
    std::cout << "[+] Loaded " << fundedAddresses.size() << " funded addresses\n";

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    std::ofstream outFile("address.txt", std::ios::app);
    size_t checked = 0;

    while (true) {
        auto privKey = generatePrivateKey();
        auto addresses = deriveAddresses(privKey, ctx);

        for (const auto& address : addresses) {
            if (fundedAddresses.find(address) != fundedAddresses.end()) {
                std::string hexKey = toHex(privKey);
                std::cout << "[MATCH] " << address << " | PrivKey: " << hexKey << "\n";
                outFile << address << " " << hexKey << "\n";
                outFile.flush();
            }
        }

        if (++checked % 10000 == 0) {
            std::cout << "[*] Checked: " << checked << " keys\n";
        }
    }

    secp256k1_context_destroy(ctx);
    return 0;
}
