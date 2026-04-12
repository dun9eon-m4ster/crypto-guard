#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <stdexcept>

TEST(CryptoGuardCtx, EncryptInError) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream src("Hello world!");
    src.setstate(std::ios_base::failbit);
    std::stringstream dst;

    ASSERT_THROW(ctx.EncryptFile(src, dst, "qwerty"), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptOutError) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream src("Hello world!");
    std::stringstream dst;
    dst.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.EncryptFile(src, dst, "qwerty"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptInError) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream src("ciphered data");
    src.setstate(std::ios_base::failbit);
    std::stringstream dst;

    ASSERT_THROW(ctx.DecryptFile(src, dst, "qwerty"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptOutError) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream src("ciphered data");
    {
        std::stringstream encrypted;
        ctx.EncryptFile(src, encrypted, "qwerty");
        src = std::move(encrypted);
    }
    std::stringstream dst;
    dst.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.DecryptFile(src, dst, "qwerty"), std::runtime_error);
}

TEST(CryptoGuardCtx, ComplexCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string data = "Hello world!";
    const std::string password = "qwerty";

    std::stringstream encrypted;
    {
        std::stringstream src(data);
        ctx.EncryptFile(src, encrypted, password);
    }

    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, password);

    EXPECT_NE(encrypted.str(), decrypted.str());
    EXPECT_EQ(decrypted.str(), data);
}

TEST(CryptoGuardCtx, Checksum) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream stream("1");

    auto checksum = ctx.CalculateChecksum(stream);
    EXPECT_EQ(checksum, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b");
}