#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace Utils {
std::vector<unsigned char> read_file(const std::string &filename);
};

#endif