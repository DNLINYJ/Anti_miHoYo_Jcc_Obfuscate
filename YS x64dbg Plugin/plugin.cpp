#include "plugin.h"
#include <json/json.h>
#include <string>
#include <iostream> 
#include <regex>
#include <fstream>
#include <pthread.h>
using namespace std;

enum
{
    MENU_SEE
};

struct datas
{
    string address; // 跳转指令所在的地址
    duint offset; // 跳转指令所在的地址偏移量
    long long jmp_address; // 跳转指令要跳转的地址
};

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
    _plugin_menuaddentry(hMenu, MENU_SEE, u8"开始监视StartDecrypt中的JMP指令断点");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case MENU_SEE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[原神反混淆插件] 开始监视StartDecrypt中的JMP指令断点.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[原神反混淆插件] 开始监视StartDecrypt中的JMP指令断点.\n");
        pthread_t tids_start; // 定义线程的 id 变量
        pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // 使用多线程启动监视进程,避免X64DBG卡死（假无响应）
        //pthread_join(tids_start, NULL);
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
        Json::Value jmp_list;
        Json::Value mov_list;
        Json::Value temp_list;

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
            if (v2 > 2) { //当一个地址出现2次以上时，认为被断点阻断或发生故障
                v2 = 0;
                duint uiAddr = 0;
                GuiSelectionGet(GUI_DISASSEMBLY, &sel);
                uiAddr = sel.start; //获取当前地址

                DbgDisasmFastAt(uiAddr, &basicinfo);  //获取当前指令

                string temp_s = basicinfo.instruction;
                string::size_type idx = temp_s.find("jmp"); //检测当前指令是否为jmp指令，避免程序发生故障所导致的阻断
                if (idx != string::npos) {  //指令为jmp指令

                    if (is_jmp_instruction(temp_s) == true) {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            _plugin_logprintf(u8"[原神反混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志

                            temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // 获取jmp指令使用的寄存器
                            duint jmp_address = DbgValFromString(temp_s.c_str());  // 获取jmp指令跳转的地址
                            _plugin_logprintf(u8"[原神反混淆插件] JMP指令跳转的地址 : 0x%p\n", jmp_address); //打印日志

                            if (jmp_list.isMember(DecIntToHexStr(uiAddr - base_address)) == false) {
                                temp_list.append(jmp_address);
                                jmp_list[DecIntToHexStr(uiAddr - base_address)] = temp_list;
                                string instruction = "jmp " + jmp_address;
                                DbgAssembleAt(uiAddr, instruction.c_str());
                                Json::Value temp_list;
                            }
                            else {
                                jmp_list[DecIntToHexStr(uiAddr - base_address)].append(jmp_address);
                            }

                            DbgCmdExecDirect("StepInto"); // 让程序单步运行
                        }
                        else {
                            break;
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

                else {
                    string::size_type idx_ = temp_s.find("mov");
                    if (idx_ != string::npos) {  //指令为mov指令
                        if (is_mov_instruction(temp_s) == true) {
                            if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                                _plugin_logprintf(u8"[原神反混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志

                                temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 8, ""); // 获取mov指令使用的寄存器
                                duint mov_address = DbgValFromString(temp_s.c_str());  // 获取mov指令地址

                                if (mov_list.isMember(DecIntToHexStr(uiAddr - base_address)) == false) {
                                    temp_list.append(mov_address);
                                    mov_list[DecIntToHexStr(uiAddr - base_address)] = temp_list;
                                    _plugin_logprintf(u8"[原神反混淆插件] [%s] : %s\n", uiAddr, mov_address);
                                    Json::Value temp_list;
                                }
                                else {
                                    mov_list[DecIntToHexStr(uiAddr - base_address)].append(mov_address);
                                }

                                DbgCmdExecDirect("StepInto"); // 让程序单步运行
                            }
                            else {
                                break;
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
                    else {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            DbgCmdExecDirect("StepInto"); // 让程序单步运行
                        }
                        else {
                            break;
                        }
                    }
                }
            }
        }
        _plugin_logprintf(u8"[原神反混淆插件] 完成.");
    }
}

bool is_mov_instruction(const std::string& instruction) {
    //00007FFE7A635B0C | 48:8B04C1                | mov rax,qword ptr ds:[rcx+rax*8]        |
    const std::regex pattern("mov r\\w\\w,qword ptr ds:[r\\w\\w+r\\w\\w\*8]");
    return std::regex_match(instruction, pattern);
}

bool is_jmp_instruction(const std::string& instruction) {
    const std::regex pattern("jmp r\\w\\w");
    return std::regex_match(instruction, pattern);
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