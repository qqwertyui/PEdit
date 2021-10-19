#include <array>
#include <boost/program_options.hpp>
#include <iostream>
#include <spdlog/spdlog.h>

#include "PE.hpp"
#include "Utils.hpp"

namespace po = boost::program_options;

namespace Version {
constexpr int MAJOR = 0;
constexpr int MINOR = 1;
} // namespace Version

namespace Status {
constexpr int OK = 0;
constexpr int MISSING_ARGS = 1;
constexpr int INPUT_ERROR = 2;
constexpr int PE_ERROR = 3;
constexpr int INVALID_OPERATION = 4;
} // namespace Status

int main(int argc, char **argv) {
  spdlog::set_pattern("[%^%l%$] %v");
  std::string input_file, output_file, section_name, operation, dump_type,
      section_file;
  int section_size = -1;
  try {
    /*
    Assign default values
    */
    dump_type = "hex";
    operation = "list";

    po::options_description desc("Avalible options");
    desc.add_options()("help", "produce help message")(
        "input", po::value<std::string>(),
        "input file")("output", po::value<std::string>(), "output file")(
        "section", po::value<std::string>(),
        "section name")("operation", po::value<std::string>(),
                        "dump, add, remove, resize, set, list")(
        "size", po::value<int>(),
        "section size")("dump_type", po::value<std::string>(), "file, hex")(
        "section_file", po::value<std::string>(),
        "section input")("version", "print application version");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") > 0) {
      std::cerr << desc << "\n";
      return Status::OK;
    }
    if (vm.count("version") > 0) {
      spdlog::info("PE modifier {}.{}", Version::MAJOR, Version::MINOR);
      return Status::OK;
    }
    if (vm.count("input") == 0) {
      spdlog::error("You must supply input file (--input)");
      return Status::MISSING_ARGS;
    }
    if (vm.count("operation") == 0) {
      spdlog::error("You must supply operation (--operation)");
      return Status::MISSING_ARGS;
    }
    if (vm.count("section") > 0) {
      section_name = vm["section"].as<std::string>();
    }
    if (vm.count("section_file") > 0) {
      section_file = vm["section_file"].as<std::string>();
    }
    if (vm.count("output") > 0) {
      output_file = vm["output"].as<std::string>();
    }
    if (vm.count("dump_type") > 0) {
      dump_type = vm["dump_type"].as<std::string>();
    }
    if (vm.count("size") > 0) {
      section_size = vm["size"].as<int>();
      if (section_size < 0) {
        spdlog::error("--size cannot be negative number");
        return Status::INPUT_ERROR;
      }
    }
    input_file = vm["input"].as<std::string>();
    operation = vm["operation"].as<std::string>();

    if (output_file.empty()) {
      output_file = input_file;
    }

  } catch (const std::exception &e) {
    spdlog::error("Parsing error: {}", e.what());
    return Status::INPUT_ERROR;
  } catch (...) {
    spdlog::error("Unknown parsing error");
    return Status::INPUT_ERROR;
  }

  PE *p1 = nullptr;
  try {
    p1 = new PE(input_file);
  } catch (const std::exception &e) {
    spdlog::error("PE module error: {}", e.what());
    return Status::PE_ERROR;
  }

  bool section_name_required = false;
  std::array<std::string, 4> requires_section_name = {"dump", "remove",
                                                      "resize", "set"};
  for (std::string &op : requires_section_name) {
    if (op.compare(operation) == 0) {
      section_name_required = true;
    }
  }

  Section *s = nullptr;
  if (section_name_required) {
    if (section_name.empty()) {
      spdlog::error("You must supply section name (--section)");
      return Status::MISSING_ARGS;
    } else {
      if (section_name.compare("add") !=
          0) { // TODO: change it to be easier managable (algorithm?)
        s = p1->get_section_by_name(section_name);
        if (s == nullptr) {
          spdlog::error("Given section doesn't exist");
          return Status::INPUT_ERROR;
        }
      }
    }
  }

  if (operation.compare("dump") == 0) {
    if (dump_type.compare("hex") == 0) {
      s->hexdump();
    } else if (dump_type.compare("file") == 0) {
      if(output_file.compare(input_file) == 0) {
        spdlog::error("--output is required");
        return Status::MISSING_ARGS;
      }
      s->filedump(output_file);
    } else {
      spdlog::error("Invalid --dump_type value");
    }
    return Status::OK;
  } else if (operation.compare("remove") == 0) {
    p1->remove_section(s);
  } else if (operation.compare("resize") == 0) {
    if (section_size < 0) {
      spdlog::error("--size <number> is required");
      return Status::MISSING_ARGS;
    }
    try {
      p1->resize_section(s, section_size);
    } catch (const std::exception &e) {
      spdlog::error("Resize error: {}", e.what());
      return Status::PE_ERROR;
    }
  } else if (operation.compare("set") == 0) {
    // TODO: implement set options
  } else if (operation.compare("add") == 0) {
    if (section_file.empty()) {
      spdlog::error("--section_file <path> is required");
      return Status::MISSING_ARGS;
    }
    std::vector<unsigned char> data;
    try {
      data = Utils::read_file(section_file);
    } catch (const std::exception &e) {
      spdlog::error("Add failure: {}", e.what());
      return Status::INPUT_ERROR;
    }
    p1->add_section(section_name, data);
  } else if (operation.compare("list") == 0) {
    std::vector<std::string> names = p1->get_section_names();
    unsigned int index = 0;
    for (std::string &n : names) {
      printf("%02u: %s\n", index, n.c_str());
      index += 1;
    }
    return Status::OK;
  } else {
    spdlog::error("Invalid operation");
    return Status::INVALID_OPERATION;
  }

  try {
    p1->dump(output_file);
  } catch (const std::exception &e) {
    spdlog::error("Dump error: {}", e.what());
    return Status::PE_ERROR;
  }

  spdlog::info("Ok");
  return Status::OK;
}