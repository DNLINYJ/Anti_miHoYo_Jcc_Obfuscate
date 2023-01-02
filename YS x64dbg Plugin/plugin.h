#pragma once

#include "pluginmain.h"
#include <string>

//plugin data
#define PLUGIN_NAME "Anti miHoYo Jcc Obfuscate"
#define PLUGIN_VERSION 1

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();
std::string DecIntToHexStr(long long num);
void get_obfuscated_address_offset();
bool is_mov_instruction(const std::string& instruction);
bool is_add_instruction(const std::string& instruction);
bool is_lea_instruction(const std::string& instruction);
bool is_jmp_instruction(const std::string& instruction);