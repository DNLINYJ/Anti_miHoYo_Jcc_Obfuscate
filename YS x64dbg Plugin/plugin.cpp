#include "plugin.h"
#include "GetWebIndex.h"
#include <json/json.h>
#include <string>
#include <iostream> 
#include <fstream>
#include <pthread.h>
using namespace std;

enum
{
    MENU_TEST,
    MENU_SEE,
    MENU_DELETE
};

struct datas
{
    string address; // 跳转指令所在的地址
    duint offset; // 跳转指令所在的地址偏移量
    long long jmp_address; // 跳转指令要跳转的地址
};

datas* get_jmp_address(int v1); // 设置get_jmp_address的函数声明
                                // 不知道为什么这玩意放 plugin.h 里面就疯狂报错，现在就这样用

//Initialize your plugin data here. 在此处初始化您的插件数据。
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here. 在此处取消初始化您的插件数据。
bool pluginStop()
{
    return true;
}

//Do GUI/Menu related things here. 在这里做 GUI/Menu 相关的事情。
void pluginSetup()
{
	//往插件菜单里面添加三个菜单项
	_plugin_menuaddentry(hMenu, MENU_TEST, u8"在JMP指令地址设置断点");
    _plugin_menuaddentry(hMenu, MENU_SEE, u8"开始监视JMP指令断点");
    _plugin_menuaddentry(hMenu, MENU_DELETE, u8"删除所有断点");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case MENU_TEST:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[原神反混淆插件] 开始在JMP指令地址设置断点.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[原神反混淆插件] 开始在JMP指令地址设置断点.\n");
        pthread_t tids; // 定义线程的 id 变量
        pthread_create(&tids, NULL, SetBreakpoint_And_Fuck_JMP, NULL); // 使用多线程启动JMP指令地址设置断点线程,避免X64DBG卡死（假无响应）
        break;
    case MENU_SEE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[原神反混淆插件] 开始监视JMP指令断点.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[原神反混淆插件] 开始监视JMP指令断点.\n");
        pthread_t tids_start; // 定义线程的 id 变量
        pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // 使用多线程启动监视进程,避免X64DBG卡死（假无响应）
        break;
    case MENU_DELETE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[原神反混淆插件] 开始删除所有断点.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[原神反混淆插件] 开始删除所有断点.\n");
        pthread_t tids_delete; // 定义线程的 id 变量
        pthread_create(&tids_delete, NULL, (void* (__cdecl*)(void*))detele_all_breakpoints, NULL); // 使用多线程启动监视进程,避免X64DBG卡死（假无响应）
        break;
    default:
        break;
    }
}

// 函数用处DOC : https://gitee.com/suxuss/DELPHI-x96dbg-Plugins-SDK/blob/master/bridgemain.pas
// 部分函数用法来源：http://www.xeronichs.com/2016/11/study-x64dbg-plugin-03.html

void get_obfuscated_address_offset()
{
    if (!DbgIsDebugging())
    {
        GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
    }
        
    else 
    {
        int v2 = 0;
        duint first_address = 0;
        duint base_address = DbgModBaseFromName("unityplayer.dll"); //模块名转基址
        string init_command_1 = "bp " + DecIntToHexStr(base_address + 0x158210); //StartDecrypt入口断点
        string init_command_2 = "bp " + DecIntToHexStr(base_address + 0x158BFB); //StartDecrypt出口断点
        DbgCmdExecDirect(init_command_1.c_str());
        DbgCmdExecDirect(init_command_2.c_str());

        while (1)
        {
            BASIC_INSTRUCTION_INFO basicinfo;
            SELECTIONDATA sel;
            GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
            if (v2 == 0) {  //当v2为0时，认为还没有记录地址或未被断点停止运行
                first_address = sel.start;
            }
            if (sel.start == first_address) { //当当前地址于第一次记录的地址相同时，v2（地址出现次数）加1
                v2 += 1;
            }
            if (v2 > 3) { //当一个地址出现3次以上时，认为被断点阻断或发生故障
                v2 = 0;
                duint uiAddr = 0;
                GuiSelectionGet(GUI_DISASSEMBLY, &sel);
                uiAddr = sel.start; //获取当前地址

                DbgDisasmFastAt(uiAddr, &basicinfo);  //获取当前指令

                string temp_s = basicinfo.instruction;
                string::size_type idx = temp_s.find("jmp"); //检测当前指令是否为jmp指令，避免程序发生故障所导致的阻断
                if (idx != string::npos) {  //指令为jmp指令
                    string url = "http://127.0.0.1:50000/check_jmp_command?c=" + temp_s;
                    string result = get_web(url);

                    if (atof(result.c_str()) > 0.6) {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            _plugin_logprintf(u8"[原神反混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志

                            temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // 获取jmp指令使用的寄存器
                            duint jmp_address = DbgValFromString(temp_s.c_str());  // 获取jmp指令跳转的地址
                            _plugin_logprintf(u8"[原神反混淆插件] JMP指令跳转的地址 : 0x%p\n", jmp_address); //打印日志

                            string temp_offset = DecIntToHexStr(uiAddr - base_address);
                            url = "http://127.0.0.1:50000/jmp_address?offset=" + temp_offset + "&jmp_offset=" + DecIntToHexStr(jmp_address - base_address); //改用GET协议进行数据传输
                            string result = get_web(url); // 发送偏移量数据到本地WEB服务器，由Python脚本进一步处理

                            if (result == "OK") {
                                _plugin_logprintf(u8"[原神反混淆插件] 成功将偏移量数据发送到本地WEB服务器.\n"); //打印日志
                                // jmp有时会跳转到其他的地址（跳转地址不唯一），所以匹配到断点后不能禁用断点
                                DbgCmdExecDirect("StepInto"); // 让程序单步运行
                            }
                            else {
                                _plugin_logprintf(u8"[原神反混淆插件] 将偏移量数据发送到本地WEB服务器失败,WEB服务器回包: %s\n", result.c_str()); //打印日志
                                DbgCmdExecDirect("StepInto"); // 让程序单步运行
                            }
                        }
                        else {
                            break;
                        }
                    }
                }
                else {
                    idx = temp_s.find("mov");
                    if (idx != string::npos) {  //指令为mov指令
                        string url = "http://127.0.0.1:50000/check_mov_command?c=" + temp_s;
                        string result = get_web(url);

                        if (atof(result.c_str()) > 0.7) {
                            if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                                _plugin_logprintf(u8"[原神反混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志

                                temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // 获取mov指令使用的寄存器
                                duint mov_address = DbgValFromString(temp_s.c_str());  // 获取mov指令地址

                                url = "http://127.0.0.1:50000/jmp_address?offset=" + DecIntToHexStr(uiAddr - base_address) + "&mov_offset=" + DecIntToHexStr(mov_address); //改用GET协议进行数据传输
                                string result = get_web(url); // 发送偏移量数据到本地WEB服务器，由Python脚本进一步处理

                                if (result == "OK") {
                                    _plugin_logprintf(u8"[原神反混淆插件] 成功将偏移量数据发送到本地WEB服务器.\n"); //打印日志
                                    // jmp有时会跳转到其他的地址（跳转地址不唯一），所以匹配到断点后不能禁用断点
                                    DbgCmdExecDirect("StepInto"); // 让程序单步运行
                                }
                                else {
                                    _plugin_logprintf(u8"[原神反混淆插件] 将偏移量数据发送到本地WEB服务器失败,WEB服务器回包: %s\n", result.c_str()); //打印日志
                                    DbgCmdExecDirect("StepInto"); // 让程序单步运行
                                }
                            }
                            else {
                                break;
                            }
                        }
                    }
                    else {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            DbgCmdExecDirect("StepInto"); // 让程序单步运行
                        }
                        else {
                            break;
                        }
                    }
                }
            DbgCmdExecDirect("StepInto"); // 让程序单步运行
            }
        }
        _plugin_logprintf(u8"[原神反混淆插件] 完成.");
    }
}

// 将10进制字符串转为16进制字符串 来源：https://blog.csdn.net/u014602230/article/details/52752683/
string DecIntToHexStr(long long num)
{
    string str;
    long long Temp = num / 16;
    int left = num % 16;
    if (Temp > 0)
        str += DecIntToHexStr(Temp);
    if (left < 10)
        str += (left + '0');
    else
        str += ('A' + left - 10);
    return str;

}