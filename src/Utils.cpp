#include "Utils.hpp"
#include <fstream>
#include <stdexcept>

std::vector<unsigned char> Utils::read_file(const std::string &filename) {
  std::vector<unsigned char> result;
  std::ifstream file(filename, std::ifstream::binary);
  if (file.good() == false) {
    throw std::runtime_error("File read error");
  }
  file.seekg(0, std::ifstream::end);
  unsigned int size = file.tellg();
  file.seekg(0, std::ifstream::beg);

  result.resize(size);
  file.read((char *)result.data(), result.size());
  file.close();
  return result;
}