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
    string address; // ��תָ�����ڵĵ�ַ
    duint offset; // ��תָ�����ڵĵ�ַƫ����
    long long jmp_address; // ��תָ��Ҫ��ת�ĵ�ַ
};

datas* get_jmp_address(int v1); // ����get_jmp_address�ĺ�������
                                // ��֪��Ϊʲô������� plugin.h ����ͷ�񱨴����ھ�������

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
	_plugin_menuaddentry(hMenu, MENU_TEST, u8"��JMPָ���ַ���öϵ�");
    _plugin_menuaddentry(hMenu, MENU_SEE, u8"��ʼ����JMPָ��ϵ�");
    _plugin_menuaddentry(hMenu, MENU_DELETE, u8"ɾ�����жϵ�");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch (info->hEntry)
    {
    case MENU_TEST:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[ԭ�񷴻������] ��ʼ��JMPָ���ַ���öϵ�.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[ԭ�񷴻������] ��ʼ��JMPָ���ַ���öϵ�.\n");
        pthread_t tids; // �����̵߳� id ����
        pthread_create(&tids, NULL, SetBreakpoint_And_Fuck_JMP, NULL); // ʹ�ö��߳�����JMPָ���ַ���öϵ��߳�,����X64DBG������������Ӧ��
        break;
    case MENU_SEE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[ԭ�񷴻������] ��ʼ����JMPָ��ϵ�.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[ԭ�񷴻������] ��ʼ����JMPָ��ϵ�.\n");
        pthread_t tids_start; // �����̵߳� id ����
        pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // ʹ�ö��߳��������ӽ���,����X64DBG������������Ӧ��
        break;
    case MENU_DELETE:
        if (!DbgIsDebugging())
        {
            GuiAddLogMessage(u8"[ԭ�񷴻������] ����Ҫ���ڵ���״̬����ʹ�ô˹���!\n");
            break;
        }
        MessageBoxA(hwndDlg, "[ԭ�񷴻������] ��ʼɾ�����жϵ�.", PLUGIN_NAME, MB_ICONINFORMATION);
        GuiAddLogMessage(u8"[ԭ�񷴻������] ��ʼɾ�����жϵ�.\n");
        pthread_t tids_delete; // �����̵߳� id ����
        pthread_create(&tids_delete, NULL, (void* (__cdecl*)(void*))detele_all_breakpoints, NULL); // ʹ�ö��߳��������ӽ���,����X64DBG������������Ӧ��
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
            if (v2 > 3) { //��һ����ַ����3������ʱ����Ϊ���ϵ���ϻ�������
                v2 = 0;
                duint uiAddr = 0;
                GuiSelectionGet(GUI_DISASSEMBLY, &sel);
                uiAddr = sel.start; //��ȡ��ǰ��ַ

                DbgDisasmFastAt(uiAddr, &basicinfo);  //��ȡ��ǰָ��

                string temp_s = basicinfo.instruction;
                string::size_type idx = temp_s.find("jmp"); //��⵱ǰָ���Ƿ�Ϊjmpָ�������������������µ����
                if (idx != string::npos) {  //ָ��Ϊjmpָ��
                    string url = "http://127.0.0.1:50000/check_jmp_command?c=" + temp_s;
                    string result = get_web(url);

                    if (atof(result.c_str()) > 0.6) {
                        if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                            _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־

                            temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                            duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                            _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־

                            string temp_offset = DecIntToHexStr(uiAddr - base_address);
                            url = "http://127.0.0.1:50000/jmp_address?offset=" + temp_offset + "&jmp_offset=" + DecIntToHexStr(jmp_address - base_address); //����GETЭ��������ݴ���
                            string result = get_web(url); // ����ƫ�������ݵ�����WEB����������Python�ű���һ������

                            if (result == "OK") {
                                _plugin_logprintf(u8"[ԭ�񷴻������] �ɹ���ƫ�������ݷ��͵�����WEB������.\n"); //��ӡ��־
                                // jmp��ʱ����ת�������ĵ�ַ����ת��ַ��Ψһ��������ƥ�䵽�ϵ���ܽ��öϵ�
                                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                            }
                            else {
                                _plugin_logprintf(u8"[ԭ�񷴻������] ��ƫ�������ݷ��͵�����WEB������ʧ��,WEB�������ذ�: %s\n", result.c_str()); //��ӡ��־
                                DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                            }
                        }
                        else {
                            break;
                        }
                    }
                }
                else {
                    idx = temp_s.find("mov");
                    if (idx != string::npos) {  //ָ��Ϊmovָ��
                        string url = "http://127.0.0.1:50000/check_mov_command?c=" + temp_s;
                        string result = get_web(url);

                        if (atof(result.c_str()) > 0.7) {
                            if (DecIntToHexStr(uiAddr) != DecIntToHexStr(base_address + 0x158BFB)) {
                                _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־

                                temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡmovָ��ʹ�õļĴ���
                                duint mov_address = DbgValFromString(temp_s.c_str());  // ��ȡmovָ���ַ

                                url = "http://127.0.0.1:50000/jmp_address?offset=" + DecIntToHexStr(uiAddr - base_address) + "&mov_offset=" + DecIntToHexStr(mov_address); //����GETЭ��������ݴ���
                                string result = get_web(url); // ����ƫ�������ݵ�����WEB����������Python�ű���һ������

                                if (result == "OK") {
                                    _plugin_logprintf(u8"[ԭ�񷴻������] �ɹ���ƫ�������ݷ��͵�����WEB������.\n"); //��ӡ��־
                                    // jmp��ʱ����ת�������ĵ�ַ����ת��ַ��Ψһ��������ƥ�䵽�ϵ���ܽ��öϵ�
                                    DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                                }
                                else {
                                    _plugin_logprintf(u8"[ԭ�񷴻������] ��ƫ�������ݷ��͵�����WEB������ʧ��,WEB�������ذ�: %s\n", result.c_str()); //��ӡ��־
                                    DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
                                }
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
            DbgCmdExecDirect("StepInto"); // �ó��򵥲�����
            }
        }
        _plugin_logprintf(u8"[ԭ�񷴻������] ���.");
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