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
            GuiAddLogMessage(u8"[���׹���CFG�������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[���׹���CFG�������] ��ʼ����StartDecrypt�е�JMPָ��ϵ�.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[���׹���CFG�������] ��ʼ����StartDecrypt�е�JMPָ��ϵ�.\n");
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
        GuiAddLogMessage(u8"[���׹���CFG�������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
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
                GuiAddLogMessage(u8"[���׹���CFG�������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
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
                if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == false) { // jmp��ַδִ�й�
                    string temp_s = basicinfo.instruction;
                    temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                    
                    duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                    _plugin_logprintf(u8"[���׹���CFG�������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־
                    _plugin_logprintf(u8"[���׹���CFG�������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־
                    temp_list.append(temp_s);
                    temp_list.append(jmp_address);

                    Json::Value normal_instruction;
                    while (true) {
                        // ��ȡ��һ��ָ��Ŀ�ʼ��ַ
                        duint temp_address = uiAddr;
                        string x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                        DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                        temp_address = DbgValFromString(x64dbg_instruction.c_str());

                        // ��addָ���������Ƿ�������ָ��
                        if (is_add_instruction(basicinfo.instruction)) {
                            int is_entry = 0;
                            duint v1 = temp_address;
                            string x64dbg_instruction = "dis.next(0x" + DecIntToHexStr(temp_address) + ")";
                            DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                            temp_address = DbgValFromString(x64dbg_instruction.c_str());

                            // jmpָ��ǰ������ָ��
                            if (!is_jmp_instruction(basicinfo.instruction)) {
                                is_entry = 1; 
                            }

                            if (is_entry) {
                                // ��ӵ�һ����������ָ��
                                normal_instruction.append(basicinfo.instruction);

                                // ��ѭ����������ָ��
                                while (true) { 
                                    string x64dbg_instruction = "dis.next(0x" + DecIntToHexStr(temp_address) + ")";
                                    DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                                    temp_address = DbgValFromString(x64dbg_instruction.c_str());

                                    if (is_jmp_instruction(basicinfo.instruction)) {
                                        break;
                                    }
                                    else {
                                        normal_instruction.append(basicinfo.instruction);
                                    }
                                }
                            }
                            // ��ԭ��ַ
                            temp_address = v1;
                        }

                        // ��movָ���ȡjmpָ����صļĴ���
                        if (is_mov_instruction(basicinfo.instruction)) {
                            smatch match;
                            regex pattern_1("r[abcd]x\\*8");
                            regex pattern_2("r[abcd]x");
                            string str = basicinfo.instruction;

                            regex_search(str, match, pattern_1);

                            if (match.size() == 1) {
                                string v2 = match[0];
                                smatch match_2;
                                regex_search(str, match_2, pattern_2);
                                v2 = match_2[0];
                                duint mov_value = DbgValFromString(v2.c_str());  // ��ȡjmpָ����صļĴ���ֵ
                                temp_list.append(v2);
                                temp_list.append(mov_value);
                            }
                        }

                        // ��leaָ���ԭָ��
                        if (is_lea_instruction(basicinfo.instruction)) {
                            // jmpָ��ǰ������ָ��
                            if (normal_instruction.empty()){ 
                                string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
                                _plugin_logprintf(u8"[���׹���CFG�������] ����ַ 0x%p �޸�Ϊ����jmpָ�� %s \n", temp_address, instruction.c_str());
                                DbgAssembleAt(temp_address, instruction.c_str());
                            }
                            // jmpָ��ǰ������ָ��
                            else {
                                int normal_instruction_size = normal_instruction.size();
                                for (int i = 0; i < normal_instruction_size; ++i) {
                                    // �ָ�����ָ��
                                    string instruction = normal_instruction[i].asCString();
                                    _plugin_logprintf(u8"[���׹���CFG�������] �ڵ�ַ 0x%p �ָ�����ָ�� %s\n", temp_address, instruction.c_str());
                                    DbgAssembleAt(temp_address, instruction.c_str());

                                    // ��ȡ��һ��ָ�ʼ��ַ
                                    x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                                    DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                                    temp_address = DbgValFromString(x64dbg_instruction.c_str());
                                }

                                string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
                                _plugin_logprintf(u8"[���׹���CFG�������] ����ַ 0x%p �޸�Ϊ����jmpָ�� %s \n", temp_address, instruction.c_str());
                                DbgAssembleAt(temp_address, instruction.c_str());
                            }
                            jmp_list[DecIntToHexStr(temp_address)] = temp_list;
                            temp_list.clear();
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

                string now_instruction = basicinfo.instruction;
                if (now_instruction.find("cmp") != string::npos) {
                    DbgCmdExecDirect("StepInto");
                }

                // ��ȡԭ���޸ĵ�jump��ַ
                string x64dbg_instruction = "dis.brtrue(0x" + DecIntToHexStr(uiAddr) + ")";
                DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                duint old_jump_to_address = DbgValFromString(x64dbg_instruction.c_str());

                // ��ȡ���ڵ�jump��ַ
                duint new_jump_to_address = DbgValFromString(jmp_list[DecIntToHexStr(uiAddr)][0].asCString());

                // ����ַ��ͬʱ �����в���
                if (old_jump_to_address == new_jump_to_address) {
                    DbgCmdExecDirect("StepInto");
                }
                // ����ַ����ͬʱ ���в���
                else {
                    // д����תָ��
                    string cmp_instruction = "cmp " + jmp_list[DecIntToHexStr(uiAddr)][2].asString() + "," + jmp_list[DecIntToHexStr(uiAddr)][3].asString();
                    string je_instruction = "je 0x" + DecIntToHexStr(old_jump_to_address);
                    string jmp_instruction = "jmp 0x" + DecIntToHexStr(new_jump_to_address);

                    _plugin_logprintf(u8"[���׹���CFG�������] �ڵ�ַ 0x%p ��ʼ�ָ���תָ�� \n", uiAddr);

                    // д��cmpָ��
                    duint temp_address = uiAddr;
                    DbgAssembleAt(temp_address, cmp_instruction.c_str());

                    // ��ȡ��һ��ָ�ʼ��ַ
                    x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                    DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                    temp_address = DbgValFromString(x64dbg_instruction.c_str());

                    // д��jeָ��
                    DbgAssembleAt(temp_address, je_instruction.c_str());

                    // ��ȡ��һ��ָ�ʼ��ַ
                    x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                    DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                    temp_address = DbgValFromString(x64dbg_instruction.c_str());

                    // д��jmpָ��
                    DbgAssembleAt(temp_address, jmp_instruction.c_str());

                    // ��ȡ��һ��ָ�ʼ��ַ
                    x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
                    DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
                    temp_address = DbgValFromString(x64dbg_instruction.c_str());
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