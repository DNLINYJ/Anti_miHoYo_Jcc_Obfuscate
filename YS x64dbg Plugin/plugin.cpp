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
        duint first_address = 0;
        duint uiAddr = 0;
        duint base_address = DbgModBaseFromName("unityplayer.dll"); //模块名转基址
        string init_command_1 = "bp " + DecIntToHexStr(base_address + 0x158210); //StartDecrypt入口断点
        string init_command_2 = "bp " + DecIntToHexStr(base_address + 0x158BFB); //StartDecrypt出口断点
        DbgCmdExecDirect(init_command_1.c_str());
        DbgCmdExecDirect(init_command_2.c_str());
        Json::Value jmp_list;
        Json::Value mov_list;
        Json::Value temp_list;

        while (true) {
            if (!DbgIsDebugging())
            {
                GuiAddLogMessage(u8"[原神反混淆插件] 你需要处于调试状态才能使用此功能!\n");
                break;
            }
            Sleep(10);
            BASIC_INSTRUCTION_INFO basicinfo;
            SELECTIONDATA sel;
            GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
            uiAddr = sel.start; //获取当前地址

            DbgDisasmFastAt(uiAddr, &basicinfo);  //获取当前指令

            if (DecIntToHexStr(sel.start) == DecIntToHexStr(base_address + 0x158BFB)) {
                break;
            }

            char* module_name = new char[256];
            bool ret = DbgGetModuleAt(uiAddr, module_name);
            string module_name_str = module_name;
            //_plugin_logprintf(module_name_str.c_str());
            if (module_name_str != "unityplayer") {
                DbgCmdExecDirect("StepInto");
                continue;
            }

            bool jmp_status = is_jmp_instruction(basicinfo.instruction);
            if (jmp_status) {
                if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == false) {
                    string temp_s = basicinfo.instruction;
                    temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // 获取jmp指令使用的寄存器
                    duint jmp_address = DbgValFromString(temp_s.c_str());  // 获取jmp指令跳转的地址
                    _plugin_logprintf(u8"[原神反混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志
                    _plugin_logprintf(u8"[原神反混淆插件] JMP指令跳转的地址 : 0x%p\n", jmp_address); //打印日志

                    duint temp_address = uiAddr - 0x7;

                    temp_list.append(temp_s);
                    temp_list.append(DecIntToHexStr(jmp_address));
                    jmp_list[DecIntToHexStr(temp_address)] = temp_list;
                    temp_list.clear();

                    string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
                    _plugin_logprintf(u8"[原神反混淆插件] 将地址 0x%p 的指令 %s 改为 %s\n", temp_address, basicinfo.instruction, instruction.c_str());
                    DbgAssembleAt(temp_address, instruction.c_str());

                    DbgDisasmFastAt(uiAddr - 7, &basicinfo);
                    string temp_string = basicinfo.instruction;
                    if (temp_string.find("add") != string::npos) {
                        _plugin_logprintf(u8"[原神反混淆插件] 在jmp指令地址 0x%p 有有用代码在Jmp指令之前！建议自动处理后手动处理！");
                    }

                    temp_address = uiAddr - 1;
                    for (int i = 0; i <= 20; i++) {
                        DbgDisasmFastAt(temp_address, &basicinfo);
                        if (is_mov_instruction(basicinfo.instruction)) {    
                            string str = basicinfo.instruction;
                            smatch result;
                            string::const_iterator iterStart = str.begin();
                            string::const_iterator iterEnd = str.end();
                            regex pattern("\\+r\\w\\w");
                            regex_search(iterStart, iterEnd, result, pattern);
                            string register_ = result[0];

                            temp_list.append(register_.replace(register_.begin(), register_.begin() + 1, ""));
                            temp_list.append(DecIntToHexStr(DbgValFromString(register_.replace(register_.begin(), register_.begin() + 1, "").c_str())));
                            mov_list[DecIntToHexStr(uiAddr)] = temp_list;
                            temp_list.clear();
                            break;
                        }
                        else {
                            temp_address = temp_address - basicinfo.size;
                        }
                    }

                    DbgCmdExecDirect("StepInto");
                }
            }
            else if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == true) { // 当jmp地址运行过了

                /*
                00007FFE857782D8 | 2D 02210000              | sub eax,2102                            |
                00007FFE857782DD | 0F95C1                   | setne cl                                |
                00007FFE857782E0 | 83F1 29                  | xor ecx,29                              |
                00007FFE857782E3 | 48:8D05 F6895A02         | lea rax,qword ptr ds:[7FFE87D20CE0]     |
                00007FFE857782EA | 48:8B04C8                | mov rax,qword ptr ds:[rax+rcx*8]        |
                00007FFE857782EE | 48:05 8D39FFFF           | add rax,FFFFFFFFFFFF398D                |
                00007FFE857782F4 | 8BB5 B0000000            | mov esi,dword ptr ss:[rbp+B0]           |
                00007FFE857782FA | 41:89F6                  | mov r14d,esi                            |
                00007FFE857782FD | 48:8BBD A8000000         | mov rdi,qword ptr ss:[rbp+A8]           |
                00007FFE85778304 | 8B9D A0000000            | mov ebx,dword ptr ss:[rbp+A0]           |
                00007FFE8577830A | 48:8B75 10               | mov rsi,qword ptr ss:[rbp+10]           |
                00007FFE8577830E | FFE0                     | jmp rax                                 |
                */

                if (DecIntToHexStr(uiAddr).find("jmp") != string::npos){
                    Sleep(10000);
                    duint jmp_address = DbgValFromString(jmp_list[DecIntToHexStr(uiAddr)][0].asCString());  // 获取jmp指令跳转的地址
                    temp_list.clear();

                    duint lea_instruction_start_address = 0;
                    duint lea_instruction_end_address = 0;

                    if (jmp_list[DecIntToHexStr(uiAddr)][1].asString() != DecIntToHexStr(jmp_address)) { // 当jmp地址不一样

                        string normal_instruction[20];
                        duint temp_address = uiAddr - 1;
                        DbgDisasmFastAt(temp_address, &basicinfo);
                        if (is_add_instruction(basicinfo.instruction) == false) {
                            _plugin_logprintf(u8"[原神反汇编插件] jmp指令前有正常指令，正在保存");
                            int a = 0;
                            for (int i = 0; i <= 100; i++) {
                                // 获取上一条指令的开始地址
                                string x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                                DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                                temp_address = DbgValFromString(x64dbg_instruction.c_str());

                                string temp_string = basicinfo.instruction;
                                if (is_add_instruction(basicinfo.instruction) == false) {
                                    if (a == 0) {
                                        normal_instruction[a] = temp_string;
                                        a++;
                                    }
                                    if (normal_instruction[a - 1].find(temp_string) == string::npos) { // 若正常指令未出现过
                                        normal_instruction[a] = temp_string;
                                        a++;
                                    }
                                }
                                else {
                                    break;
                                }
                            }
                        }

                        temp_address = uiAddr - 1;
                        for (int i = 0; i <= 100; i++) { // 向上搜索lea指令开始地址
                            DbgDisasmFastAt(temp_address, &basicinfo);
                            string temp_string = basicinfo.instruction;

                            if (is_lea_instruction(temp_string) == true) {
                                lea_instruction_start_address = temp_address - basicinfo.size + 1;
                                break;
                            }
                            else if (basicinfo.size == 1 || temp_string == "???") { // 识别不到正常指令
                                temp_address = temp_address - basicinfo.size;
                            }
                            else {
                                temp_address = temp_address - basicinfo.size;
                            }
                        }

                        duint instruction_start_address = 0;
                        duint normal_instruction_start_address = lea_instruction_start_address;

                        if (normal_instruction[0].empty() == false) { // jmp指令前存在正常指令
                            for (int i = 0; i <= 20; i++) {
                                if (normal_instruction[i].empty() == false) {
                                    DbgAssembleAt(normal_instruction_start_address, normal_instruction[i].c_str());
                                    DbgDisasmFastAt(normal_instruction_start_address, &basicinfo);
                                    normal_instruction_start_address = normal_instruction_start_address + basicinfo.size; // 指向下一条指令的开始地址
                                }
                                else {
                                    break;
                                }
                            }
                        }

                        if (normal_instruction_start_address != lea_instruction_start_address) { // 若已经修正正常指令
                            instruction_start_address = normal_instruction_start_address;
                        }
                        else {
                            instruction_start_address = lea_instruction_start_address;
                        }
                        
                        string temp_cmp_instruction = "cmp " + mov_list[DecIntToHexStr(uiAddr)][0].asString() + ", 0x" + mov_list[DecIntToHexStr(uiAddr)][1].asString();
                        string temp_je_instruction = "je 0x" + jmp_list[DecIntToHexStr(uiAddr)][1].asString();
                        string temp_jmp_instruction = "jmp 0x" + DecIntToHexStr(jmp_address);

                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[原神反混淆插件] 将地址 0x%p 的指令 %s 改为 %s\n", instruction_start_address, basicinfo.instruction, temp_cmp_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_cmp_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // 指向下一条指令的开始地址


                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[原神反混淆插件] 将地址 0x%p 的指令 %s 改为 %s\n", instruction_start_address, basicinfo.instruction, temp_je_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_je_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // 指向下一条指令的开始地址
                        
                        
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[原神反混淆插件] 将地址 0x%p 的指令 %s 改为 %s\n", instruction_start_address, basicinfo.instruction, temp_jmp_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_jmp_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // 指向下一条指令的开始地址

                        DbgCmdExecDirect("StepInto");
                    }
                    else {
                        DbgCmdExecDirect("StepInto");
                    }
                }
                else {
                    DbgCmdExecDirect("StepInto");
                }
            }
            else {
                DbgCmdExecDirect("StepInto");
            }
        }
    }
}


bool is_mov_instruction(const std::string& instruction) {
    //00007FFE7A635B0C | 48:8B04C1                | mov rax, qword ptr ds:[rcx+rax*8]        |
    const std::regex pattern("mov r\\w\\w, qword ptr ds:\\[r\\w\\w\\+r\\w\\w\\*8\\]");
    if (std::regex_match(instruction, pattern)) {
        return 1;
    }
    else {
        const std::regex pattern("mov r\\w\\w, qword ptr ds : \\[r\\w\\w \\+ r\\w\\w\\*8\\]");
        if (std::regex_match(instruction, pattern)) {
            return 1;
        }
        else {
            return 0;
        }
    }
}

bool is_add_instruction(const std::string& instruction) {
    const std::regex pattern("add r\\w\\w,FFFFFFFF\\w\\w\\w\\w\\w\\w\\w\\w");
    return std::regex_match(instruction, pattern);
}

bool is_lea_instruction(const std::string& instruction) {
    const std::regex pattern("lea r\\w\\w,qword ptr ds:\\[\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\]");
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