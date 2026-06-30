#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <ios>
#include <iostream>
#include <print>
#include <stdexcept>

std::fstream GetOutputFile(const std::string &filename) {
    if (filename.empty())
        throw std::runtime_error{"Missing output filename"};

    std::fstream file(filename, std::ios::out | std::ios::trunc);
    if (!file.is_open())
        throw std::runtime_error{"Unable to open output file"};

    if (file.good() == false)
        throw std::runtime_error{"Input stream error"};

    return file;
}

std::fstream GetInputFile(const std::string &filename) {
    if (filename.empty())
        throw std::runtime_error{"Missing input filename"};

    std::fstream file(filename, std::ios::in);
    if (!file.is_open())
        throw std::runtime_error{"Unable to open input file"};

    if (file.good() == false)
        throw std::runtime_error{"Output stream error"};

    return file;
}

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.isHelp())
            return 0;

        if (options.GetInputFile() == options.GetOutputFile()) {
            std::print("Input and output files are same\n");
            return 1;
        }

        std::fstream src = GetInputFile(options.GetInputFile());
        CryptoGuard::CryptoGuardCtx ctx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::UNDEFINED:
            std::print("No command specified\n");
            break;

        case COMMAND_TYPE::ENCRYPT: {
            std::fstream dst = GetOutputFile(options.GetOutputFile());
            ctx.EncryptFile(src, dst, options.GetPassword());
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream dst = GetOutputFile(options.GetOutputFile());
            ctx.DecryptFile(src, dst, options.GetPassword());
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::cout << ctx.CalculateChecksum(src) << std::endl;
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}