#ifndef PE_HPP
#define PE_HPP

#include <windows.h>
#include <winnt.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class PE;

/**
 * @brief 
 * This class represents single PE file section.
 * It contains both header and the content of the section.
 */
class Section {
public:
  IMAGE_SECTION_HEADER header;
  std::vector<BYTE> code;

  /**
   * @brief 
   * Prints hexdump of section.
   */
  void hexdump() const;
  /**
   * @brief 
   * Writes section body into given filename.
   * @param[in] filename 
   * Output filename.
   */
  void filedump(const std::string &filename) const;

private:
  void resize(size_t new_size);
  friend class PE;
};

/**
 * @brief 
 * Represents DOS header and the code it contains.
 */
class Image_Dos {
public:
  IMAGE_DOS_HEADER dosHeader;
  std::vector<BYTE> code;
};

/**
 * @brief 
 * Represents PE (Portable Executable) file
 */
class PE {
public:
  /**
   * @brief 
   * Represents application type, e.g.
   * GUI -> Graphical application
   * CUI -> Console application
   */
  enum Subsystem {
    UNKNOWN = IMAGE_SUBSYSTEM_UNKNOWN,
    NATIVE = IMAGE_SUBSYSTEM_NATIVE,
    GUI = IMAGE_SUBSYSTEM_WINDOWS_GUI,
    CUI = IMAGE_SUBSYSTEM_WINDOWS_CUI
  };

  /**
   * @brief Construct a new PE object
   * 
   * @param[in] application_type Output application type
   */
  explicit PE(PE::Subsystem application_type);

  /**
   * @brief Load existing PE file into memory
   * 
   * @param[in] filename Path to executable
   */
  explicit PE(const std::string &filename);
  ~PE();

  /**
   * @brief Checks section existence
   * 
   * @param[in] section Pointer to existing Section* object
   * @return true if section exists
   * @return false otherwise
   */
  bool section_exists(const Section *section) const;

  /**
   * @brief Gets the section by its name
   * 
   * @param[in] name Section name 
   * @return Section* object if section was found, nullptr otherwise
   */
  Section *get_section_by_name(std::string name) const;

  /**
   * @brief Add new section
   * 
   * @param section_name New section name
   * @param[in] data Section contents
   * @return newly created Section* in case of success, or pointer to existing Section* 
   * object if given section_name existed before, in both cases it overwrites
   * section content
   */
  Section *add_section(std::string section_name,
                       std::vector<unsigned char> &data);

  /**
   * @brief Removes section
   * 
   * @param[in] section Pointer to existing Section* object
   * @note If section is nullptr the function does nothing
   */
  void remove_section(Section *section);

  /**
   * @brief Overwrites existing section contents
   * 
   * @param[in] section Pointer to existing Section* object
   * @param[in] data Data that will be written
   * @note If section is nullptr the function does nothing
   */
  void write_section(Section *section, std::vector<unsigned char> &data);

  /**
   * @brief Set the program enty point
   * 
   * @param[in] section Section in which the entry point is to be set
   * @param[in] offset Offset in the given section
   * @note If section is nullptr the function does nothing
   */
  void set_entry_point(Section *section, size_t offset);

  /**
   * @brief Resizes section body
   * 
   * @param[in] section Section in which the size is to be changed
   * @param[in] new_size New section size
   */
  void resize_section(Section *section, size_t new_size);

  /**
   * @brief Returns std::vector which contain section names
   */
  std::vector<std::string> get_section_names() const;

  /**
   * @brief Dumps contents of PE file onto disk
   * 
   * @param[in] name Output file name 
   */
  void dump(const std::string &name);

private:
  enum Alignment { FILE = 0x200, MEMORY = 0x1000 };
  static int32_t align(size_t size, Alignment to);

  static int32_t compute_checksum(const std::string &filename);
  static int32_t get_section_specific_flags(std::string section_name);
  static bool is_pe(const std::vector<unsigned char> &bytes);

  static constexpr int PAGE_SIZE = 0x1000;
  static constexpr int MAX_STUB_SIZE = 0x40;

  static constexpr std::array<unsigned char, MAX_STUB_SIZE> dos_stub_code = {
      0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01,
      0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x02, 0x70, 0x72, 0x6F,
      0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74,
      0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20,
      0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D,
      0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static constexpr std::array<unsigned char, 6> default_x86_code = {
      0xB8, 0x39, 0x05, 0x00, 0x00, 0xC3};

  // Header objects
  Image_Dos dosHeaderInfo;
  IMAGE_NT_HEADERS32 ntHeader;
  std::vector<Section *> sections;

  // Utils
  Section *rva_to_section(size_t rva);
  size_t section_to_rva(Section *section);

  void fill_section_specific(Section *section);

  friend class Section;
};

typedef std::vector<Section*>::iterator Section_Iterator;

#endif
