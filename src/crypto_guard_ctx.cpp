
#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <exception>
#include <ios>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;
    using ChecksumCtx = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    template <typename InBuffArray, typename OutBuffArray>
    void encryptDecrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, bool is_encrypt,
                        InBuffArray &inBuff, OutBuffArray &outBuff) {
        auto ctx = CipherCtx(EVP_CIPHER_CTX_new());

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = is_encrypt ? 1 : 0;
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        size_t inBufSize = 0;
        auto processBuffer = [&]() {
            int out_len = 0;
            EVP_CipherUpdate(ctx.get(), outBuff.data(), &out_len, inBuff.data(), inBufSize);
            for (int i = 0; i < out_len; ++i) {
                outStream << outBuff[i];
                if (outStream.good() == false)
                    throw std::runtime_error{"outStream write error"};
            }
            inBufSize = 0;
        };

        inStream >> std::noskipws;
        while (true) {
            unsigned char c;
            inStream >> c;
            if (inStream.eof()) {
                if (inBufSize != 0)
                    processBuffer();
                break;
            } else if (inStream.good() == false)
                throw std::runtime_error{"inStream read error"};

            inBuff[inBufSize++] = std::move(c);
            if (inBufSize == inBuff.size())
                processBuffer();
        }

        int outLen = 0;

        EVP_CipherFinal_ex(ctx.get(), outBuff.data(), &outLen);

        for (int i = 0; i < outLen; ++i) {
            outStream << outBuff[i];
            if (outStream.good() == false)
                throw std::runtime_error{"outStream write error"};
        }
    }

    void encryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        std::array<unsigned char, 10000> inBuff;
        std::array<unsigned char, inBuff.size() + EVP_MAX_BLOCK_LENGTH> outBuff;

        encryptDecrypt(inStream, outStream, password, true, inBuff, outBuff);
    }

    void decryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        std::array<unsigned char, 10000> inBuff;
        std::array<unsigned char, inBuff.size()> outBuff;

        encryptDecrypt(inStream, outStream, password, false, inBuff, outBuff);
    }

    std::string calculateChecksum(std::iostream &inStream) {
        auto ctx = ChecksumCtx(EVP_MD_CTX_new());

        unsigned char checksum[32]{};

        std::vector<unsigned char> inBuf;
        while (true) {
            unsigned char c;
            inStream >> c;
            if (inStream.eof())
                break;
            else if (inStream.good() == false)
                throw std::runtime_error{"inStream read error"};
            inBuf.push_back(c);
        }

        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx.get(), inBuf.data(), inBuf.size());
        EVP_DigestFinal_ex(ctx.get(), checksum, nullptr);

        std::stringstream result;

        // std::cout << "checksum raw: ";
        for (uint i = 0; i < 32; ++i) {
            // std::cout << std::hex << checksum[i];
            result << std::hex << (int)checksum[i];
        }
        // std::cout << std::endl;

        return result.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pimpl(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() {}
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pimpl->encryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pimpl->decryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pimpl->calculateChecksum(inStream); }
CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&other) noexcept { this->pimpl = std::move(other.pimpl); }
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&other) noexcept {
    this->pimpl = std::move(other.pimpl);
    return *this;
};
}  // namespace CryptoGuard
