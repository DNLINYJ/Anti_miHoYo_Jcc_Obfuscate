#include "pluginmain.h"
#include "plugin.h"

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) //初始化函数, 用于查询版本号,注册插件的名字和版本
{
    initStruct->pluginVersion = 1;  //插件的版本号
    initStruct->sdkVersion = PLUG_SDKVERSION; //PDK的版本号
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE); //插件名
    pluginHandle = initStruct->pluginHandle; //获取并保存插件句柄
    return pluginInit(initStruct); 
}

PLUG_EXPORT bool plugstop() //x64dbg退出, 插件被卸载时调用
{
    return pluginStop();
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;
    pluginSetup();
}

extern "C" PLUG_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}