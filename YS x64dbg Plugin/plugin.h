#pragma once

#include "pluginmain.h"
#include <string>

//plugin data
#define PLUGIN_NAME "YS_x64dbg_Plugin"
#define PLUGIN_VERSION 1

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();
void *SetBreakpoint_And_Fuck_JMP(void*); // 为了多线程才改成void指针
std::string DecIntToHexStr(long long num);
void get_obfuscated_address_offset();
bool check_now_module(duint address);
std::string get_jmp_offset_file_path();
void detele_all_breakpoints();