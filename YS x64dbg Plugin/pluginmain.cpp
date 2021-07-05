#include "pluginmain.h"
#include "plugin.h"

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) //��ʼ������, ���ڲ�ѯ�汾��,ע���������ֺͰ汾
{
    initStruct->pluginVersion = 1;  //����İ汾��
    initStruct->sdkVersion = PLUG_SDKVERSION; //PDK�İ汾��
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE); //�����
    pluginHandle = initStruct->pluginHandle; //��ȡ�����������
    return pluginInit(initStruct); 
}

PLUG_EXPORT bool plugstop() //x64dbg�˳�, �����ж��ʱ����
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