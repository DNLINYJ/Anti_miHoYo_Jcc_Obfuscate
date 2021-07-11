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

            bool mov_status = is_mov_instruction(basicinfo.instruction);

            if (mov_status) {
                _plugin_logprintf(u8"%s\n", basicinfo.instruction);
                if (mov_list.isMember(DecIntToHexStr(uiAddr)) == false) { // ��ȡrxx����
                    //����������
                    string str = basicinfo.instruction;
                    smatch result;
                    string::const_iterator iterStart = str.begin();
                    string::const_iterator iterEnd = str.end();
                    regex pattern("\\+r\\w\\w");
                    regex_search(iterStart, iterEnd, result, pattern);
                    string register_ = result[0];
                    mov_list[DecIntToHexStr(uiAddr)] = DecIntToHexStr(DbgValFromString(register_.replace(register_.begin(), register_.begin() + 1, "").c_str()));
                    string temp_temp = DecIntToHexStr(uiAddr);

                    int v1 = 0;
                    for (int i = 0; i <= 20; i++) {
                        BASIC_INSTRUCTION_INFO basicinfo_;
                        DbgDisasmFastAt(uiAddr + i, &basicinfo_);
                        if (is_jmp_instruction(basicinfo_.instruction)) {
                            string temp_command = "bp " + DecIntToHexStr(uiAddr + i);
                            v1 = i;
                            DbgCmdExecDirect(temp_command.c_str());
                            DbgCmdExecDirect("run");
                            break;
                        }
                    }

                    Sleep(50);
                    string temp_command = "bpc " + DecIntToHexStr(uiAddr + v1);
                    DbgCmdExecDirect(temp_command.c_str());
                    BASIC_INSTRUCTION_INFO basicinfo_;
                    DbgDisasmFastAt(uiAddr + v1, &basicinfo_);  //��ȡ��ǰָ��
                    string temp_s = basicinfo_.instruction;
                    temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                    duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                    _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr + v1, basicinfo_.instruction); //��ӡ��־
                    _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־

                    jmp_list[temp_temp] = DecIntToHexStr(jmp_address);
                    string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
                    DbgAssembleAt(uiAddr, instruction.c_str());
                }

                else {
                    _plugin_logprintf(u8"0x%p\n", uiAddr);
                    Sleep(2000);
                    string str = basicinfo.instruction;
                    smatch result;
                    string::const_iterator iterStart = str.begin();
                    string::const_iterator iterEnd = str.end();
                    regex pattern("\\+r\\w\\w");
                    regex_search(iterStart, iterEnd, result, pattern);
                    string register_ = result[0];
                    if (mov_list[DecIntToHexStr(uiAddr)] != DecIntToHexStr(DbgValFromString(register_.replace(register_.begin(), register_.begin() + 1, "").c_str()))) {
                        string temp_string = ".+?" + register_.replace(register_.begin(), register_.begin() + 1, "") + ".+";
                        regex pattern(temp_string);
                        for (int i = 0; i <= 150; i++) {
                            DbgDisasmFastAt(uiAddr - i, &basicinfo);
                            string temp_instruction = basicinfo.instruction;
                            if (std::regex_match(temp_instruction, pattern)) {
                                string temp_cmp_instruction = "cmp " + register_ + ",0x" + mov_list[DecIntToHexStr(uiAddr)].asString();
                                DbgAssembleAt(uiAddr - i + 1, temp_cmp_instruction.c_str());
                                regex pattern_("cmp");
                                for (int x = 1; x <= 10; x++) {
                                    DbgDisasmFastAt(uiAddr - i + x, &basicinfo);
                                    temp_instruction = basicinfo.instruction;
                                    if (!std::regex_match(temp_instruction, pattern_)) {
                                        string temp_je_instruction = "je " + jmp_list[DecIntToHexStr(uiAddr)].asString();
                                        DbgAssembleAt(uiAddr - i + x, temp_je_instruction.c_str());

                                        int v1 = 0;
                                        for (int i_ = 0; i_ <= 20; i_++) {
                                            BASIC_INSTRUCTION_INFO basicinfo_;
                                            DbgDisasmFastAt(uiAddr + i_, &basicinfo_);
                                            if (is_jmp_instruction(basicinfo_.instruction)) {
                                                string temp_command = "bp " + DecIntToHexStr(uiAddr + i_);
                                                v1 = i_;
                                                DbgCmdExecDirect(temp_command.c_str());
                                                DbgCmdExecDirect("run");
                                                break;
                                            }
                                        }

                                        Sleep(50);
                                        string temp_command = "bpc " + DecIntToHexStr(uiAddr + v1);
                                        DbgCmdExecDirect(temp_command.c_str());
                                        BASIC_INSTRUCTION_INFO basicinfo_;
                                        DbgDisasmFastAt(uiAddr + v1, &basicinfo_);  //��ȡ��ǰָ��
                                        string temp_s = basicinfo_.instruction;
                                        temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                                        duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                                        _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr + v1, basicinfo_.instruction); //��ӡ��־
                                        _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־
                                        string temp_jmp_instruction = "jmp " + jmp_address;
                                        DbgAssembleAt(uiAddr - i + x + 7, temp_jmp_instruction.c_str());
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                mov_status = false;
            }
            else {
                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                if (DecIntToHexStr(sel.start) == DecIntToHexStr(base_address + 0x158BFB)) {
                    pthread_exit(0);
                    _plugin_logprintf(u8"[ԭ�񷴻������] ���.");
                    break;
                }
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