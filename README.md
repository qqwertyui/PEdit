# PEdit
### About project

PEdit is tool I have written and I'm currently improving to simplify my experiments with 32 bit Portable Executable files. In the future there may appear integration with QT so console may no longer be the only interface.

### What it can be used for?

PEdit can manipulate PE file sections e.g. add, remove, show or change their content. Some options may break binaries you operate on so be carefull what you are doing (For example deleting .text section may not be good idea, because you basically delete all of your executable code). All in all, you need what you want to do before use, this tool doesn't do everything for user and at the end of the day it's only about convinence (so you don't have to make changes in hex editor).

## 1. BUILD
Requirements:
To be able to build this project you need to have working Boost.Build module installed (https://www.boost.org/doc/libs/1_62_0/more/getting_started/windows.html#id27), so:
- g++ with c++17 support 
- Boost.Build
- Boost.Program_options
- spdlog
You need to change your compiler version in Jamfile:1; it can be found by "g++ --version", e.g:
g++.exe (x86_64-posix-seh-rev0, Built by MinGW-W64 project) 8.1.0 <---
                                                            -----

git clone https://github.com/qqwertyui/PEdit.git && cd PEdit
b2 pedit release

The output binary can be found at %REPOSITORY_ROOT%/bin/gcc-%COMPILER_VERSION%/release/pedit.exe

## 2. USAGE
#### Get help
./pedit --help

#### Print version
./pedit --version

#### List avalible sections
./pedit --input sample.exe --operation list

#### Remove .tls section in sample.exe
./pedit --input sample.exe --operation remove --section ".tls"

#### Remove .tls section, leave sample.exe unchanged and write result in result.exe
./pedit --input sample.exe --operation remove --section ".tls" --output result.exe

#### Resize .data section
./pedit --input sample.exe --operation resize --section ".data" --size 2048

#### Hexdump .rsrc section
./pedit --input sample.exe --operation dump --section ".rsrc" --dump_type hex

#### Extract .rsrc section to file
./pedit --input sample.exe --operation dump --section ".rsrc" --dump_type file --output rsrc_section.blob

#### Documentation generation 
doxygen 
##### Output can be found int ./doc