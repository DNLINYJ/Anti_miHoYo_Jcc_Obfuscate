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
    string address; // ��תָ�����ڵĵ�ַ
    duint offset; // ��תָ�����ڵĵ�ַƫ����
    long long jmp_address; // ��תָ��Ҫ��ת�ĵ�ַ
};

//Initialize your plugin data here. �ڴ˴���ʼ�����Ĳ�����ݡ�
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here. �ڴ˴�ȡ����ʼ�����Ĳ�����ݡ�
bool pluginStop()
{
    return true;
}

//Do GUI/Menu related things here. �������� GUI/Menu ��ص����顣
void pluginSetup()
{
	//������˵�������������˵���
    _plugin_menuaddentry(hMenu, MENU_SEE, u8"��ʼ����StartDecrypt�е�JMPָ��ϵ�");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case MENU_SEE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[ԭ�񷴻������] ��ʼ����StartDecrypt�е�JMPָ��ϵ�.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[ԭ�񷴻������] ��ʼ����StartDecrypt�е�JMPָ��ϵ�.\n");
        pthread_t tids_start; // �����̵߳� id ����
        pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // ʹ�ö��߳��������ӽ���,����X64DBG������������Ӧ��
        //pthread_join(tids_start, NULL);
        break;
    default:
        break;
    }
}

// �����ô�DOC : https://gitee.com/suxuss/DELPHI-x96dbg-Plugins-SDK/blob/master/bridgemain.pas
// ���ֺ����÷���Դ��http://www.xeronichs.com/2016/11/study-x64dbg-plugin-03.html

void get_obfuscated_address_offset()
{
    if (!DbgIsDebugging())
    {
        GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
    }

    else
    {
        duint first_address = 0;
        duint uiAddr = 0;
        duint base_address = DbgModBaseFromName("unityplayer.dll"); //ģ����ת��ַ
        string init_command_1 = "bp " + DecIntToHexStr(base_address + 0x158210); //StartDecrypt��ڶϵ�
        string init_command_2 = "bp " + DecIntToHexStr(base_address + 0x158BFB); //StartDecrypt���ڶϵ�
        DbgCmdExecDirect(init_command_1.c_str());
        DbgCmdExecDirect(init_command_2.c_str());
        Json::Value jmp_list;
        Json::Value mov_list;
        Json::Value temp_list;

        while (true) {
            if (!DbgIsDebugging())
            {
                GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
                break;
            }
            Sleep(10);
            BASIC_INSTRUCTION_INFO basicinfo;
            SELECTIONDATA sel;
            GuiSelectionGet(GUI_DISASSEMBLY, &sel); //��ȡָ�� GUI ��ͼ�ĵ�ǰѡ���У�����У�������Ϣ��Ϊ��ʼ��ַ�ͽ�����ַ���ص� SELECTIONDATA �����С�
            uiAddr = sel.start; //��ȡ��ǰ��ַ

            DbgDisasmFastAt(uiAddr, &basicinfo);  //��ȡ��ǰָ��

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
                    temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                    duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                    _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־
                    _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־

                    duint temp_address = uiAddr - 0x7;

                    temp_list.append(temp_s);
                    temp_list.append(DecIntToHexStr(jmp_address));
                    jmp_list[DecIntToHexStr(temp_address)] = temp_list;
                    temp_list.clear();

                    string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
                    _plugin_logprintf(u8"[ԭ�񷴻������] ����ַ 0x%p ��ָ�� %s ��Ϊ %s\n", temp_address, basicinfo.instruction, instruction.c_str());
                    DbgAssembleAt(temp_address, instruction.c_str());

                    DbgDisasmFastAt(uiAddr - 7, &basicinfo);
                    string temp_string = basicinfo.instruction;
                    if (temp_string.find("add") != string::npos) {
                        _plugin_logprintf(u8"[ԭ�񷴻������] ��jmpָ���ַ 0x%p �����ô�����Jmpָ��֮ǰ�������Զ�������ֶ�����");
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
            else if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == true) { // ��jmp��ַ���й���

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
                    duint jmp_address = DbgValFromString(jmp_list[DecIntToHexStr(uiAddr)][0].asCString());  // ��ȡjmpָ����ת�ĵ�ַ
                    temp_list.clear();

                    duint lea_instruction_start_address = 0;
                    duint lea_instruction_end_address = 0;

                    if (jmp_list[DecIntToHexStr(uiAddr)][1].asString() != DecIntToHexStr(jmp_address)) { // ��jmp��ַ��һ��

                        string normal_instruction[20];
                        duint temp_address = uiAddr - 1;
                        DbgDisasmFastAt(temp_address, &basicinfo);
                        if (is_add_instruction(basicinfo.instruction) == false) {
                            _plugin_logprintf(u8"[ԭ�񷴻����] jmpָ��ǰ������ָ����ڱ���");
                            int a = 0;
                            for (int i = 0; i <= 100; i++) {
                                DbgDisasmFastAt(temp_address, &basicinfo);
                                string temp_string = basicinfo.instruction;
                                if (basicinfo.size == 1 || temp_string == "???") { // ʶ�𲻵�����ָ��
                                    temp_address--;
                                    continue;
                                }
                                if (is_add_instruction(basicinfo.instruction) == false) {
                                    if (a == 0) {
                                        normal_instruction[a] = temp_string;
                                        a++;
                                    }
                                    if (normal_instruction[a - 1].find(temp_string) == string::npos) { // ������ָ��δ���ֹ�
                                        normal_instruction[a] = temp_string;
                                        a++;
                                    }
                                    temp_address = temp_address - basicinfo.size; // ָ����һ��ָ��Ľ�����ַ
                                }
                                else {
                                    break;
                                }
                            }
                        }

                        temp_address = uiAddr - 1;
                        for (int i = 0; i <= 100; i++) { // ��������leaָ�ʼ��ַ
                            DbgDisasmFastAt(temp_address, &basicinfo);
                            string temp_string = basicinfo.instruction;

                            if (is_lea_instruction(temp_string) == true) {
                                lea_instruction_start_address = temp_address - basicinfo.size + 1;
                                break;
                            }
                            else if (basicinfo.size == 1 || temp_string == "???") { // ʶ�𲻵�����ָ��
                                temp_address = temp_address - basicinfo.size;
                            }
                            else {
                                temp_address = temp_address - basicinfo.size;
                            }
                        }

                        duint instruction_start_address = 0;
                        duint normal_instruction_start_address = lea_instruction_start_address;

                        if (normal_instruction[0].empty() == false) { // jmpָ��ǰ��������ָ��
                            for (int i = 0; i <= 20; i++) {
                                if (normal_instruction[i].empty() == false) {
                                    DbgAssembleAt(normal_instruction_start_address, normal_instruction[i].c_str());
                                    DbgDisasmFastAt(normal_instruction_start_address, &basicinfo);
                                    normal_instruction_start_address = normal_instruction_start_address + basicinfo.size; // ָ����һ��ָ��Ŀ�ʼ��ַ
                                }
                                else {
                                    break;
                                }
                            }
                        }

                        if (normal_instruction_start_address != lea_instruction_start_address) { // ���Ѿ���������ָ��
                            instruction_start_address = normal_instruction_start_address;
                        }
                        else {
                            instruction_start_address = lea_instruction_start_address;
                        }
                        
                        string temp_cmp_instruction = "cmp " + mov_list[DecIntToHexStr(uiAddr)][0].asString() + ", 0x" + mov_list[DecIntToHexStr(uiAddr)][1].asString();
                        string temp_je_instruction = "je 0x" + jmp_list[DecIntToHexStr(uiAddr)][1].asString();
                        string temp_jmp_instruction = "jmp 0x" + DecIntToHexStr(jmp_address);

                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[ԭ�񷴻������] ����ַ 0x%p ��ָ�� %s ��Ϊ %s\n", instruction_start_address, basicinfo.instruction, temp_cmp_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_cmp_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // ָ����һ��ָ��Ŀ�ʼ��ַ


                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[ԭ�񷴻������] ����ַ 0x%p ��ָ�� %s ��Ϊ %s\n", instruction_start_address, basicinfo.instruction, temp_je_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_je_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // ָ����һ��ָ��Ŀ�ʼ��ַ
                        
                        
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        _plugin_logprintf(u8"[ԭ�񷴻������] ����ַ 0x%p ��ָ�� %s ��Ϊ %s\n", instruction_start_address, basicinfo.instruction, temp_jmp_instruction.c_str());
                        DbgAssembleAt(instruction_start_address, temp_jmp_instruction.c_str());
                        DbgDisasmFastAt(instruction_start_address, &basicinfo);
                        instruction_start_address = instruction_start_address + basicinfo.size; // ָ����һ��ָ��Ŀ�ʼ��ַ

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


// ��10�����ַ���תΪ16�����ַ��� ��Դ��https://blog.csdn.net/u014602230/article/details/52752683/
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