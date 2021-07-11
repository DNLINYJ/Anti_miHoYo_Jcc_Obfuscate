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
        int v2 = 0;
        duint first_address = 0;
        duint base_address = DbgModBaseFromName("unityplayer.dll"); //ģ����ת��ַ
        string init_command_1 = "bp " + DecIntToHexStr(base_address + 0x158210); //StartDecrypt��ڶϵ�
        string init_command_2 = "bp " + DecIntToHexStr(base_address + 0x158BFB); //StartDecrypt���ڶϵ�
        DbgCmdExecDirect(init_command_1.c_str());
        DbgCmdExecDirect(init_command_2.c_str());
        Json::Value jmp_list;
        Json::Value mov_list;
        Json::Value temp_list;

        while (1)
        {
            BASIC_INSTRUCTION_INFO basicinfo;
            SELECTIONDATA sel;
            GuiSelectionGet(GUI_DISASSEMBLY, &sel); //��ȡָ�� GUI ��ͼ�ĵ�ǰѡ���У�����У�������Ϣ��Ϊ��ʼ��ַ�ͽ�����ַ���ص� SELECTIONDATA �����С�
            if (v2 == 0) {  //��v2Ϊ0ʱ����Ϊ��û�м�¼��ַ��δ���ϵ�ֹͣ����
                first_address = sel.start;
            }
            if (sel.start == first_address) { //����ǰ��ַ�ڵ�һ�μ�¼�ĵ�ַ��ͬʱ��v2����ַ���ִ�������1
                v2 += 1;
            }
            if (v2 > 2) { //��һ����ַ����2������ʱ����Ϊ���ϵ���ϻ�������
                v2 = 0;
                duint uiAddr = 0;
                GuiSelectionGet(GUI_DISASSEMBLY, &sel);
                uiAddr = sel.start; //��ȡ��ǰ��ַ

                DbgDisasmFastAt(uiAddr, &basicinfo);  //��ȡ��ǰָ��

                string temp_s = basicinfo.instruction;
                string::size_type idx = temp_s.find("jmp"); //��⵱ǰָ���Ƿ�Ϊjmpָ�������������������µ����
                if (idx != string::npos) {  //ָ��Ϊjmpָ��

                    if (is_jmp_instruction(temp_s) == true) {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־

                            temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                            duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                            _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־

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

                            DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                        }
                        else {
                            break;
                        }
                    }
                }

                else {
                    string::size_type idx_ = temp_s.find("mov");
                    if (idx_ != string::npos) {  //ָ��Ϊmovָ��
                        if (is_mov_instruction(temp_s) == true) {
                            if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                                _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־

                                temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 8, ""); // ��ȡmovָ��ʹ�õļĴ���
                                duint mov_address = DbgValFromString(temp_s.c_str());  // ��ȡmovָ���ַ

                                if (mov_list.isMember(DecIntToHexStr(uiAddr - base_address)) == false) {
                                    temp_list.append(mov_address);
                                    mov_list[DecIntToHexStr(uiAddr - base_address)] = temp_list;
                                    _plugin_logprintf(u8"[ԭ�񷴻������] [%s] : %s\n", uiAddr, mov_address);
                                    Json::Value temp_list;
                                }
                                else {
                                    mov_list[DecIntToHexStr(uiAddr - base_address)].append(mov_address);
                                }

                                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                            }
                            else {
                                break;
                            }
                        }
                        else {
                            if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                            }
                            else {
                                break;
                            }
                        }
                    }
                    else {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                        }
                        else {
                            break;
                        }
                    }
                }
            }
        }
        _plugin_logprintf(u8"[ԭ�񷴻������] ���.");
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