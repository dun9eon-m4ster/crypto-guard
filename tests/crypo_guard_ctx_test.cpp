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

TEST(CryptoGuardCtx, AnotherChecksum) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream stream(
        "Crime and Punishment follows the mental anguish and moral dilemmas of Rodion Raskolnikov, an impoverished "
        "former law student in Saint Petersburg who plans to kill an unscrupulous pawnbroker, an old woman who stores "
        "money and valuable objects in her flat. He theorises that with the money he could liberate himself from "
        "poverty and go on to perform great deeds, and seeks to convince himself that certain crimes are justifiable "
        "if they are committed in order to remove obstacles to the higher goals of extraordinary men. Once the "
        "deed is done, however, he finds himself wracked with confusion, paranoia, and disgust. His theoretical "
        "justifications lose all their power as he struggles with guilt and horror and is confronted with both "
        "internal and external consequences of his deed.");

    auto checksum = ctx.CalculateChecksum(stream);
    EXPECT_EQ(checksum, "e4603bb8366f3c0c2d2920480509a1b815b11cda2ab75ea2de6b65a3cc67d477");
}

TEST(CryptoGuardCtx, ChecksumInvalidInput) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream invalid_stream;
    invalid_stream.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.CalculateChecksum(invalid_stream), std::runtime_error);
}