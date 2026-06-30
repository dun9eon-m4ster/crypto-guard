#include "cmd_options.h"
#include <gtest/gtest.h>
#include <string>

using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

TEST(ProgramOptions, ContainsHelpOption) {
    char argv0[] = "app_name";
    char argv1[] = "--help";
    char *argv[] = {argv0, argv1};

    CryptoGuard::ProgramOptions options;
    options.Parse(2, argv);

    EXPECT_EQ(options.isHelp(), true);
}

TEST(ProgramOptions, NotContainsHelpOption) {
    char argv0[] = "app_name";
    char *argv[] = {argv0};

    CryptoGuard::ProgramOptions options;
    options.Parse(1, argv);

    EXPECT_EQ(options.isHelp(), false);
}

TEST(ProgramOptions, NotSetCommand) {
    char argv0[] = "app_name";
    char *argv[] = {argv0};

    CryptoGuard::ProgramOptions options;
    options.Parse(1, argv);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::UNDEFINED);
}

TEST(ProgramOptions, UnknownCommand) {
    char argv0[] = "app_name";
    char argv1[] = "--command";
    char argv2[] = "invalid_command";
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::UNDEFINED);
}

TEST(ProgramOptions, EncryptCommand) {
    char argv0[] = "app_name";
    char argv1[] = "--command";
    char argv2[] = "encrypt";
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, DecryptCommand) {
    char argv0[] = "app_name";
    char argv1[] = "--command";
    char argv2[] = "decrypt";
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ChecksumCommand) {
    char argv0[] = "app_name";
    char argv1[] = "--command";
    char argv2[] = "checksum";
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, InputFileOpt) {

    char argv0[] = "app_name";
    char argv1[] = "--input";
    char argv2[] = "src.txt";
    std::string input_file_opt = argv2;
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetInputFile(), input_file_opt);
}

TEST(ProgramOptions, OutputFileOpt) {

    char argv0[] = "app_name";
    char argv1[] = "--output";
    char argv2[] = "dst.txt";
    std::string output_file_opt = argv2;
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetOutputFile(), output_file_opt);
}

TEST(ProgramOptions, PasswordOpt) {

    char argv0[] = "app_name";
    char argv1[] = "--password";
    char argv2[] = "qwerty";
    std::string password_opt = argv2;
    char *argv[] = {argv0, argv1, argv2};

    CryptoGuard::ProgramOptions options;
    options.Parse(3, argv);

    EXPECT_EQ(options.GetPassword(), password_opt);
}

TEST(ProgramOptions, AllOpt) {
    char argv0[] = "app_name";
    char argv1[] = "--password";
    char argv2[] = "qwerty";
    std::string password_opt = argv2;
    char argv3[] = "--command";
    char argv4[] = "encrypt";
    COMMAND_TYPE command_opt = COMMAND_TYPE::ENCRYPT;
    char argv5[] = "--input";
    char argv6[] = "src.txt";
    std::string input_opt = argv6;
    char argv7[] = "--output";
    char argv8[] = "dst.txt";
    std::string output_opt = argv8;
    char *argv[] = {argv0, argv1, argv2, argv3, argv4, argv5, argv6, argv7, argv8};

    CryptoGuard::ProgramOptions options;
    options.Parse(9, argv);

    EXPECT_EQ(options.GetPassword(), password_opt);
    EXPECT_EQ(options.GetCommand(), command_opt);
    EXPECT_EQ(options.GetInputFile(), input_opt);
    EXPECT_EQ(options.GetOutputFile(), output_opt);
}