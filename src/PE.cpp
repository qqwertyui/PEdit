#include "PE.hpp"

#include <imagehlp.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <stdexcept>

PE::PE(PE::Subsystem application_type) {
  /*
          IMAGE_DOS_HEADER
  */
  this->dosHeaderInfo.dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
  this->dosHeaderInfo.dosHeader.e_cblp = 0x90;
  this->dosHeaderInfo.dosHeader.e_cp = 0x3;
  this->dosHeaderInfo.dosHeader.e_cparhdr = 0x4;
  this->dosHeaderInfo.dosHeader.e_maxalloc = 0xFFFF;
  this->dosHeaderInfo.dosHeader.e_sp = 0xB8;
  this->dosHeaderInfo.dosHeader.e_lfarlc = 0x40;
  this->dosHeaderInfo.dosHeader.e_lfanew = 0x80;

  // Standard DOS stub code, the same which appears in most PE's
  this->dosHeaderInfo.code.resize(MAX_STUB_SIZE);
  memcpy(this->dosHeaderInfo.code.data(), (void *)dos_stub_code.data(),
         dos_stub_code.size());

  /*
          signature + IMAGE_FILE_HEADER
  */
  memset(&this->ntHeader, 0, sizeof(IMAGE_NT_HEADERS));
  this->ntHeader.Signature = IMAGE_NT_SIGNATURE;
  this->ntHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;

  // 'add_section' takes care of this one
  this->ntHeader.FileHeader.NumberOfSections = 0;

  // Can be changed to spoof timestamp
  this->ntHeader.FileHeader.TimeDateStamp = std::time(0);

  // todo
  this->ntHeader.FileHeader.PointerToSymbolTable = 0;
  this->ntHeader.FileHeader.NumberOfSymbols = 0;

  // Fixed value (always?)
  this->ntHeader.FileHeader.SizeOfOptionalHeader =
      sizeof(IMAGE_OPTIONAL_HEADER32);

  // Some standard flags
  this->ntHeader.FileHeader.Characteristics =
      IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE |
      IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE |
      IMAGE_FILE_DEBUG_STRIPPED;

  /*
          IMAGE_OPTIONAL_HEADER
  */
  this->ntHeader.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

  this->ntHeader.OptionalHeader.MajorLinkerVersion = 0; // ???
  this->ntHeader.OptionalHeader.MinorLinkerVersion = 0; // ???

  // 'add_section' takes care of those
  this->ntHeader.OptionalHeader.SizeOfCode = 0;
  this->ntHeader.OptionalHeader.SizeOfInitializedData = 0;
  this->ntHeader.OptionalHeader.SizeOfUninitializedData = 0;
  this->ntHeader.OptionalHeader.AddressOfEntryPoint = 0;
  this->ntHeader.OptionalHeader.BaseOfCode = 0;
  this->ntHeader.OptionalHeader.BaseOfData = 0;

  // Standard base and alignment
  this->ntHeader.OptionalHeader.ImageBase = 0x400000;
  this->ntHeader.OptionalHeader.SectionAlignment = PE::Alignment::MEMORY;
  this->ntHeader.OptionalHeader.FileAlignment = PE::Alignment::FILE;

  // Don't know which values are ok, so using those
  this->ntHeader.OptionalHeader.MajorOperatingSystemVersion = 4;
  this->ntHeader.OptionalHeader.MinorOperatingSystemVersion = 0;
  this->ntHeader.OptionalHeader.MajorImageVersion = 1;
  this->ntHeader.OptionalHeader.MinorImageVersion = 0;
  this->ntHeader.OptionalHeader.MajorSubsystemVersion = 4;
  this->ntHeader.OptionalHeader.MinorSubsystemVersion = 0;
  this->ntHeader.OptionalHeader.Win32VersionValue = 0;

  /*
          'add_section' takes care of those (it is important
          to have appropriate values here, so be careful when
          changing anything here
  */
  this->ntHeader.OptionalHeader.SizeOfImage = 0x1000; // warning
  this->ntHeader.OptionalHeader.SizeOfHeaders =
      this->dosHeaderInfo.dosHeader.e_lfanew +
      sizeof(IMAGE_NT_HEADERS); // warning

  // 'calc_checksum' fills this field when dumping
  this->ntHeader.OptionalHeader.CheckSum = 0;

  // See constants defined in 'PE.h'
  this->ntHeader.OptionalHeader.Subsystem = application_type;

  /*
          https://docs.microsoft.com/en-us/windows/win32/\
          debug/pe-format#dll-characteristics
  */
  this->ntHeader.OptionalHeader.DllCharacteristics = 0;

  // Standard values found in other PE, seems good
  this->ntHeader.OptionalHeader.SizeOfStackReserve = 0x200000;
  this->ntHeader.OptionalHeader.SizeOfStackCommit = 0x1000;
  this->ntHeader.OptionalHeader.SizeOfHeapReserve = 0x100000;
  this->ntHeader.OptionalHeader.SizeOfHeapCommit = 0x1000;

  // "Reserved, must be zero."
  this->ntHeader.OptionalHeader.LoaderFlags = 0;

  // Fixed value (in this case), may be changed later
  this->ntHeader.OptionalHeader.NumberOfRvaAndSizes = 0x10;
  memset(this->ntHeader.OptionalHeader.DataDirectory, 0,
         sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
}

PE::PE(const std::string &filename) {
  std::ifstream file(filename, std::ifstream::binary);
  if (file.good() == false) {
    throw std::runtime_error("File error");
  }
  file.seekg(0, std::ifstream::end);
  size_t size = file.tellg();
  file.seekg(0, std::ifstream::beg);

  std::vector<unsigned char> buffer(size);
  file.read((char *)buffer.data(), size);
  file.close();

  if (PE::is_pe(buffer) == false) {
    throw std::runtime_error("Invalid PE file");
  }

  unsigned char *ptr = buffer.data();
  memcpy((char *)&this->dosHeaderInfo.dosHeader, ptr,
         sizeof(this->dosHeaderInfo.dosHeader));
  ptr += sizeof(this->dosHeaderInfo.dosHeader);

  this->dosHeaderInfo.code.resize(this->dosHeaderInfo.dosHeader.e_lfanew -
                                  sizeof(this->dosHeaderInfo.dosHeader));

  memcpy(this->dosHeaderInfo.code.data(), ptr, this->dosHeaderInfo.code.size());
  ptr += this->dosHeaderInfo.code.size();

  memcpy(&this->ntHeader, ptr, sizeof(this->ntHeader));
  ptr += sizeof(this->ntHeader);

  this->ntHeader.FileHeader.PointerToSymbolTable = 0;
  this->ntHeader.FileHeader.NumberOfSymbols = 0;

  for (size_t i = 0; i < this->ntHeader.FileHeader.NumberOfSections; i++) {
    Section *t = new Section;
    memcpy(&t->header, ptr, sizeof(t->header));
    ptr += sizeof(t->header);
    unsigned char *file_offset = ptr;

    // jump to content of section
    ptr = buffer.data() + t->header.PointerToRawData;

    t->code.resize(t->header.SizeOfRawData);
    memcpy(t->code.data(), ptr, t->header.SizeOfRawData);
    sections.push_back(t);

    // jump back to headers
    ptr = file_offset;
  }
}

PE::~PE() {
  for (Section *section : this->sections) {
    delete section;
  }
}

int32_t PE::align(size_t size, Alignment to) {
  if (size == 0) {
    return to;
  }
  return ((to - ((size - 1) % to)) + size - 1);
}

bool PE::is_pe(const std::vector<unsigned char> &bytes) {
  if (bytes.size() < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))) {
    return false;
  }
  if (memcmp(bytes.data(), "MZ", 2) != 0) {
    return false;
  }
  IMAGE_DOS_HEADER *dos_hdr = (IMAGE_DOS_HEADER *)bytes.data();
  if (memcmp(bytes.data() + dos_hdr->e_lfanew, "PE", 2) != 0) {
    return false;
  }
  return true;
}

Section *PE::add_section(std::string section_name,
                         std::vector<unsigned char> &data) {
  Section *section = this->get_section_by_name(section_name);
  if (section != nullptr) {
    this->write_section(section, data);
    return section;
  }

  this->ntHeader.FileHeader.NumberOfSections++;
  Section *sec = new Section;
  memset(&sec->header, 0, sizeof(IMAGE_SECTION_HEADER));

  memcpy(sec->header.Name, section_name.c_str(), section_name.size() + 1);
  sec->header.Misc.VirtualSize = data.size();

  if (this->sections.size() == 0) {
    size_t offset = dosHeaderInfo.dosHeader.e_lfanew +
                    sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER);
    sec->header.VirtualAddress = PAGE_SIZE;
    sec->header.PointerToRawData = PE::align(offset, PE::Alignment::FILE);
  } else {
    Section *previous_section = this->sections[this->sections.size() - 1];
    sec->header.VirtualAddress =
        previous_section->header.VirtualAddress +
        PE::align(previous_section->header.Misc.VirtualSize,
                  PE::Alignment::MEMORY);
    sec->header.PointerToRawData = previous_section->header.PointerToRawData +
                                   previous_section->header.SizeOfRawData;
  }
  sec->header.SizeOfRawData = PE::align(data.size(), PE::Alignment::FILE);
  sec->header.Characteristics = PE::get_section_specific_flags(section_name);

  sec->code.resize(sec->header.SizeOfRawData);
  memset(sec->code.data(), 0, sec->header.SizeOfRawData);
  memcpy(sec->code.data(), data.data(), data.size());

  sections.push_back(sec);
  this->fill_section_specific(sec);

  this->ntHeader.OptionalHeader.SizeOfImage +=
      PE::align(sec->header.Misc.VirtualSize, PE::Alignment::MEMORY);
  this->ntHeader.OptionalHeader.SizeOfHeaders +=
      sizeof(IMAGE_SECTION_HEADER); // it is rounded in dump method
  return sec;
}

bool PE::section_exists(const Section *section) const {
  if (section) {
    return std::any_of(
        this->sections.begin(), this->sections.end(),
        [&section](const Section *s) { return (s == section) ? true : false; });
  }
  return false;
}

void PE::resize_section(Section *section, size_t new_size) {
  this->ntHeader.OptionalHeader.SizeOfImage -=
      PE::align(section->header.Misc.VirtualSize, PE::Alignment::MEMORY);
  section->resize(new_size);
  this->ntHeader.OptionalHeader.SizeOfImage +=
      PE::align(section->header.Misc.VirtualSize, PE::Alignment::MEMORY);
}

std::vector<std::string> PE::get_section_names() const {
  std::vector<std::string> result;
  for (Section *s : this->sections) {
    result.push_back(std::string((char *)s->header.Name));
  }
  return result;
}

void PE::remove_section(Section *section) {
  if (this->section_exists(section) == false) {
    return;
  }

  this->ntHeader.FileHeader.NumberOfSections -= 1;
  this->ntHeader.OptionalHeader.SizeOfImage -=
      PE::align(section->header.Misc.VirtualSize, PE::Alignment::MEMORY);
  this->ntHeader.OptionalHeader.SizeOfHeaders -=
      sizeof(IMAGE_SECTION_HEADER); // it is rounded in dump method

  auto it = std::remove_if(
      this->sections.begin(), this->sections.end(), [&section](Section *s) {
        return (strcmp((const char *)s->header.Name,
                       (const char *)section->header.Name) == 0)
                   ? true
                   : false;
      });
  this->sections.erase(it, this->sections.end());
}

int32_t PE::get_section_specific_flags(std::string section_name) {
  if (section_name.compare(".text") == 0) {
    return (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_CNT_INITIALIZED_DATA);
  } else if (section_name.compare(".data") == 0 ||
             section_name.compare(".tls") == 0) {
    return (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE);
  } else if (section_name.compare(".rdata") == 0) {
    return (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
  } else if (section_name.compare(".bss") == 0) {
    return (IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE);
  }
  return (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
}

void PE::fill_section_specific(Section *section) {
  size_t rva = section->header.VirtualAddress;
  size_t size_raw = section->header.SizeOfRawData;
  std::string section_name = (char *)section->header.Name;

  if (section_name.compare(".text") == 0) {
    this->ntHeader.OptionalHeader.SizeOfCode =
        PE::align(size_raw, PE::Alignment::FILE);
    this->ntHeader.OptionalHeader.BaseOfCode = rva;
    this->ntHeader.OptionalHeader.AddressOfEntryPoint = rva;
  } else if (section_name.compare(".data") == 0) {
    this->ntHeader.OptionalHeader.SizeOfUninitializedData =
        PE::align(size_raw, PE::Alignment::FILE);
    this->ntHeader.OptionalHeader.BaseOfData = rva;
  }
}

void PE::dump(const std::string &name) {
  /*
  if(this->get_section_by_name(".text") == nullptr) {
    std::vector<unsigned char> temp(default_x86_code.begin(),
  default_x86_code.end()); Section *section = this->add_section(".text", temp);
    this->set_entry_point(section, 0);
  }
  */

  this->ntHeader.OptionalHeader.SizeOfHeaders = PE::align(
      this->ntHeader.OptionalHeader.SizeOfHeaders, PE::Alignment::FILE);

  std::ofstream file(name, std::ofstream::binary);
  if (file.good() == false) {
    throw std::runtime_error("File error");
  }

  // Fill IMAGE_DOS_HEADER struct
  file.write((char *)&this->dosHeaderInfo.dosHeader,
             sizeof(this->dosHeaderInfo.dosHeader));

  // Insert custom DOS program
  file.write((char *)this->dosHeaderInfo.code.data(),
             this->dosHeaderInfo.code.size());

  // Fill IMAGE_NT_HEADERS struct
  file.seekp(this->dosHeaderInfo.dosHeader.e_lfanew, std::ofstream::beg);
  file.write((char *)&this->ntHeader, sizeof(this->ntHeader));

  size_t section_offset = this->dosHeaderInfo.dosHeader.e_lfanew +
                          sizeof(this->ntHeader) +
                          this->sections.size() * sizeof(IMAGE_SECTION_HEADER);

  for (size_t i = 0; i < this->sections.size(); i++) {
    Section *section = this->sections[i];
    if (strcmp((const char *)section->header.Name, ".bss") == 0) {
      continue;
    }
    section->header.PointerToRawData =
        PE::align(section_offset, PE::Alignment::FILE);
    if (i > 0) {
      Section *previous_section = this->sections[i - 1];
      section->header.VirtualAddress =
          previous_section->header.VirtualAddress +
          PE::align(previous_section->header.Misc.VirtualSize,
                    PE::Alignment::MEMORY);
    } else {
      section->header.VirtualAddress =
          PE::align(section_offset, PE::Alignment::MEMORY);
    }
    section_offset += section->header.SizeOfRawData;
  }

  for (Section *section : this->sections) {
    file.write((char *)&section->header, sizeof(IMAGE_SECTION_HEADER));
  }

  for (size_t i = 0; i < this->sections.size(); i++) {
    Section *section = this->sections[i];
    file.seekp(section->header.PointerToRawData, std::ofstream::beg);
    file.write((char *)section->code.data(), section->header.SizeOfRawData);
  }
  file.close();

  size_t checksum = this->compute_checksum(name);
  file.open(name, std::ofstream::binary | std::ofstream::app);

  size_t offset = dosHeaderInfo.dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) -
                  (32 + sizeof(this->ntHeader.OptionalHeader.DataDirectory));

  file.seekp(offset, std::ofstream::beg);
  file.write((char *)&checksum, sizeof(checksum));
  file.close();
}

int32_t PE::compute_checksum(const std::string &filename) {
  DWORD headerSum, checkSum;
  MapFileAndCheckSumA((LPSTR)filename.c_str(), &headerSum, &checkSum);
  return checkSum;
}

void PE::write_section(Section *section, std::vector<unsigned char> &data) {
  if (this->section_exists(section) == false) {
    return;
  }
  if (section->code.size() < data.size()) {
    this->resize_section(section, data.size());
  }
  memcpy(section->code.data(), (void *)data.data(), data.size());
}

Section *PE::rva_to_section(size_t rva) {
  for (Section *section : this->sections) {
    if (section->header.VirtualAddress <= rva &&
        PE::align(section->header.SizeOfRawData, PE::Alignment::MEMORY) +
                section->header.VirtualAddress >
            rva) {
      return section;
    }
  }
  return nullptr;
}

Section *PE::get_section_by_name(std::string name) const {
  for (Section *section : this->sections) {
    if (name.compare((char *)section->header.Name) == 0) {
      return section;
    }
  }
  return nullptr;
}

size_t PE::section_to_rva(Section *section) {
  return section->header.VirtualAddress;
}

void PE::set_entry_point(Section *section, size_t offset) {
  if(section) {
    this->ntHeader.OptionalHeader.AddressOfEntryPoint =
      PE::section_to_rva(section) + offset;
  }
}

void Section::resize(size_t new_size) {
  size_t new_size_aligned = PE::align(new_size, PE::Alignment::FILE);
  this->header.SizeOfRawData = new_size_aligned;
  this->header.Misc.VirtualSize = new_size;

  std::vector<BYTE> backup = this->code;
  this->code.resize(new_size_aligned);
  memset(this->code.data(), 0, new_size_aligned);

  size_t bytes_to_copy =
      (new_size_aligned >= backup.size()) ? backup.size() : new_size_aligned;
  memcpy(this->code.data(), backup.data(), bytes_to_copy);
}

void Section::hexdump() const {
  constexpr int LINE_LENGTH = 16 * 3 + 10;
  printf("           ");
  for (int i = 0; i < 0x10; i++) {
    printf("%02x ", i);
  }
  puts("");
  for (int i = 0; i < LINE_LENGTH; i++) {
    printf("-");
  }
  int i = 0;
  for (const unsigned char &b : this->code) {
    if (i % 0x10 == 0) {
      printf("\n|%08x| ", i);
    }
    printf("%.2x ", b);
    i++;
  }
  puts("");
}

void Section::filedump(const std::string &filename) const {
  std::ofstream file(filename, std::ofstream::binary);
  if (file.good() == false) {
    throw std::runtime_error("File error");
  }
  file.write((char *)this->code.data(), this->code.size());
  file.close();
}
