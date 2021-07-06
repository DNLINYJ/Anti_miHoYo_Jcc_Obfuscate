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
    MENU_SEE
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
	//������˵�������������˵���˵�ID�ֱ���1��2��
	_plugin_menuaddentry(hMenu, MENU_TEST, u8"��JMPָ���ַ���öϵ�");
    _plugin_menuaddentry(hMenu, MENU_SEE, u8"��ʼ����JMPָ��ϵ�");
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
        pthread_t tids; // �����̵߳� id �������������ʹ������
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
        pthread_t tids_start; // �����̵߳� id �������������ʹ������
        pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // ʹ�ö��߳��������ӽ���,����X64DBG������������Ӧ��
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
            if (v2 > 5) { //��һ����ַ����5������ʱ����Ϊ���ϵ���ϻ�������
                v2 = 0;
                duint uiAddr = 0;
                duint base_address = DbgModBaseFromName("unityplayer.dll"); //ģ����ת��ַ
                uiAddr = sel.start; //��ȡ��ǰjmp��ַ
                char* module_name = new char[256];
                bool ret = DbgGetModuleAt(uiAddr, module_name);
                string module_name_str = module_name;
                //_plugin_logprintf(module_name_str.c_str());
                if (module_name_str != "unityplayer") {
                    continue;
                }
                DbgDisasmFastAt(uiAddr, &basicinfo);  //��ȡ��ǰjmpָ��

                string temp_s = basicinfo.instruction;
                string::size_type idx = temp_s.find("jmp"); //��⵱ǰָ���Ƿ�Ϊjmpָ�������������������µ����
                if (idx != string::npos) {  //ָ��Ϊjmpָ��
                    _plugin_logprintf(u8"[ԭ�񷴻������] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //��ӡ��־

                    temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // ��ȡjmpָ��ʹ�õļĴ���
                    duint jmp_address = DbgValFromString(temp_s.c_str());  // ��ȡjmpָ����ת�ĵ�ַ
                    _plugin_logprintf(u8"[ԭ�񷴻������] JMPָ����ת�ĵ�ַ : 0x%p\n", jmp_address); //��ӡ��־

                    string temp_offset = DecIntToHexStr(uiAddr - base_address);
                    string url = "http://127.0.0.1:50000/jmp_address?offset=" + temp_offset + "&jmp_offset=" + DecIntToHexStr(jmp_address - base_address); //����GETЭ��������ݴ���
                    //_plugin_logprintf(u8"[ԭ�񷴻������] [Debug] URL:",url);
                    //string post_data = "{\"offset\":\"" + temp_offset + "\",\"jmp_offset\":\"" + DecIntToHexStr(jmp_address - base_address) + "\"}"; // {"offset":jmpָ���ƫ����, "jmp_offset":jmpָ����ת�ĵ�ַƫ����}
                    string result = get_web(url); // ����ƫ�������ݵ�����WEB����������Python�ű���һ������

                    if (result == "OK") {
                        _plugin_logprintf(u8"[ԭ�񷴻������] �ɹ���ƫ�������ݷ��͵�����WEB������.\n"); //��ӡ��־
                    }
                    else {
                        _plugin_logprintf(u8"[ԭ�񷴻������] ��ƫ�������ݷ��͵�����WEB������ʧ��,WEB�������ذ�: %s\n", result.c_str()); //��ӡ��־
                    }
                    DbgCmdExecDirect("run"); // �ó����������
                }
            }
        }
    }
}

void *SetBreakpoint_And_Fuck_JMP(void* args) {
    int v1 = 0;
    duint base_address = DbgModBaseFromName("unityplayer.dll"); //ģ����ת��ַ
    while (999 - v1) {  // ��ͬ�� while (v1 != 15214)
        datas* temp = new datas;
        temp = get_jmp_address(v1); // ��ȡjmpָ���ַ
        v1++;
        string command = "bp " + DecIntToHexStr(temp->offset + base_address);  
        bool result = DbgCmdExecDirect(command.c_str()); // ʹ�� bp+��ַ ����ʽ�¶ϵ�
        
        string temp_string;
        temp_string = DecIntToHexStr(temp->offset + base_address);
        if (result == true) {  //���öϵ�ɹ�
            string info = u8"[ԭ�񷴻������] �ɹ�����JMPָ��ϵ��ڵ�ַ: " + temp_string + u8"\n";
            GuiAddLogMessage(info.c_str());
        }
        else {
            string info = u8"[ԭ�񷴻������] ����JMPָ��ϵ��ڵ�ַ: " + temp_string + u8" ʧ��.\n";
            GuiAddLogMessage(info.c_str());
        }
    }
    GuiAddLogMessage(u8"[ԭ�񷴻������] ����JMPָ���ַ�ϵ�ɹ�.\n");
}

datas* get_jmp_address(int v1) {
    fstream fin1("F:\\x64dbg_2021_03_12\\release\\x64\\plugins\\offset_jmp.json", ios::in);
    string json_text;
    getline(fin1, json_text); // ��ȡjmpָ���ŵ�Json�ļ�
    fin1.close();

    Json::Value value_json;
    Json::Reader reader_json;
    reader_json.parse(json_text.c_str(), value_json);
    datas* jmp_address_dict = new datas;
    string jmp_address_string = value_json[v1]["address"].asCString();
    jmp_address_dict->address = jmp_address_string; // ��ȡjmpָ����IDA�ڵĵ�ַ

    string temp_string = value_json[v1]["offset"].asCString();
    long long temp_long = strtol(temp_string.c_str(), 0, 16);
    duint temp_offset = static_cast<duint>(temp_long); // ��ȡjmpָ��ƫ����

    jmp_address_dict->offset = temp_offset;
    jmp_address_dict->jmp_address = 0;

    return jmp_address_dict;
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
