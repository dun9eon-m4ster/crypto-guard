#include "cmd_options.h"
#include <boost/program_options/value_semantic.hpp>
#include <iostream>
#include <print>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions()
    : command_(COMMAND_TYPE::UNDEFINED), m_is_help_triggered(false), desc_("Allowed options") {
    desc_.add_options()("help", "show this craft")("command", po::value<std::string>(), "[encrypt, decrypt, checksum]")(
        "input", po::value<std::string>(), "path to input file")(
        "output", po::value<std::string>(), "path to output file")("password", po::value<std::string>(),
                                                                   "password for commands \"encrypt\" & \"decrypt\"");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        m_is_help_triggered = true;
        return;
    } else {
        m_is_help_triggered = false;
    }

    if (vm.count("command")) {
        auto command_str = vm["command"].as<std::string>();
        auto found_command = commandMapping_.find(command_str);
        if (found_command == commandMapping_.cend()) {
            std::print("Unknown command: {}\n", command_str);
            return;
        }
        command_ = found_command->second;
    }

    if (vm.count("input"))
        inputFile_ = vm["input"].as<std::string>();

    if (vm.count("output"))
        outputFile_ = vm["output"].as<std::string>();

    if (vm.count("password"))
        password_ = vm["password"].as<std::string>();
}

bool ProgramOptions::isHelp() const { return m_is_help_triggered; }
}  // namespace CryptoGuard
