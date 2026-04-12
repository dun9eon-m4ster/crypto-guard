#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <ios>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.isHelp())
            return 0;

        // std::cout << "10 in hex is:" << std::hex << (char)10 << std::endl;

        std::fstream src(options.GetInputFile(), std::ios::in | std::ios::out);
        std::fstream dst(options.GetOutputFile(), std::ios::in | std::ios::out);

        CryptoGuard::CryptoGuardCtx ctx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::UNDEFINED:
            std::print("No command specified\n");
            break;

        case COMMAND_TYPE::ENCRYPT: {
            ctx.EncryptFile(src, dst, options.GetPassword());
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
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