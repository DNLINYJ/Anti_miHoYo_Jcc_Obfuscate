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
void static SetBreakpoint_And_Fuck_JMP();
std::string DecIntToHexStr(long long num);
void get_obfuscated_address_offset();