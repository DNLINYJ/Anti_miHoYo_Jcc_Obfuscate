#include "plugin.h"
#include <json/json.h>
#include <string>
#include <iostream> 
#include <regex>
#include <pthread.h>
using namespace std;

pthread_t tids_start; // 定义线程的 id 变量

enum
{
	MENU_SEE,
	MENU_END
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
	_plugin_menuaddentry(hMenu, MENU_END, u8"取消线程");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch (info->hEntry)
	{
	case MENU_SEE:
		if (!DbgIsDebugging())
		{
			GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 你需要处于调试状态才能使用此功能!\n");
			break;
		}
		MessageBoxA(hwndDlg, "[反米哈游CFG混淆插件] 开始监视StartDecrypt中的JMP指令断点.", PLUGIN_NAME, MB_ICONINFORMATION);
		GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 开始监视StartDecrypt中的JMP指令断点.\n");
		pthread_create(&tids_start, NULL, (void* (__cdecl*)(void*))get_obfuscated_address_offset, NULL); // 使用多线程启动监视进程,避免X64DBG卡死（假无响应）
		//pthread_join(tids_start, NULL);
		break;
	case MENU_END:
		if (!DbgIsDebugging())
		{
			GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 你需要处于调试状态才能使用此功能!\n");
			break;
		}
		MessageBoxA(hwndDlg, "[反米哈游CFG混淆插件] 开始关闭线程.", PLUGIN_NAME, MB_ICONINFORMATION);
		GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 开始关闭线程.\n");
		if (pthread_cancel(tids_start)) {
			if (!pthread_kill(tids_start, 0)) {
				GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 关闭线程失败!\n");
			}
			else {
				GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 关闭线程成功.\n");
			}
		}
		else {
			GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 关闭线程成功.\n");
		}
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
		GuiAddLogMessage(u8"[反米哈游CFG混淆插件] 你需要处于调试状态才能使用此功能!\n");
		return;
	}

	else
	{
		duint first_address = 0;
		duint uiAddr = 0;
		duint base_address = DbgModBaseFromName("unityplayer.dll"); //模块名转基址

		// StarRail 0.6
		duint startAddressRVA = 0xB8580;
		duint endAddressRVA = 0xB8696;

		string init_command_1 = "bp " + DecIntToHexStr(base_address + startAddressRVA); //StartDecrypt入口断点
		string init_command_2 = "bp " + DecIntToHexStr(base_address + endAddressRVA); //StartDecrypt出口断点
		DbgCmdExecDirect(init_command_1.c_str());
		DbgCmdExecDirect(init_command_2.c_str());
		Json::Value jmp_list;
		Json::Value temp_list;
		BASIC_INSTRUCTION_INFO basicinfo;
		SELECTIONDATA sel;
		GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
		duint ta = sel.start; //获取当前地址

		while (true) {
			string x64dbg_instruction_1 = "dis.next(0x" + DecIntToHexStr(ta) + ")";
			DbgDisasmFastAt(DbgValFromString(x64dbg_instruction_1.c_str()), &basicinfo);
			ta = DbgValFromString(x64dbg_instruction_1.c_str());

			if (is_jmp_instruction(basicinfo.instruction)) {
				x64dbg_instruction_1 = "bp " + DecIntToHexStr(ta);
				DbgCmdExecDirect(x64dbg_instruction_1.c_str());
				break;
			}
		}
		DbgCmdExecDirect("run");

		while (true) {
			if (!DbgIsDebugging())
			{
				return;
			}
			Sleep(1000);
			GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
			uiAddr = sel.start; //获取当前地址
			// 判断是否停止
			duint new_add;
			for (int i = 0; i < 10; i++) {
				Sleep(5);
				GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
				new_add = sel.start; //获取当前地址
			}

			if (new_add != uiAddr) {
				continue;
			}

			DbgDisasmFastAt(uiAddr, &basicinfo);  //获取当前指令

			if (DecIntToHexStr(sel.start) == DecIntToHexStr(base_address + endAddressRVA)) {
				return;
			}

			regex pattern("pop r");
			if (regex_match(basicinfo.instruction, pattern)) {
				return;
			}

			char* module_name = new char[256];
			bool ret = DbgGetModuleAt(uiAddr, module_name);
			string module_name_str = module_name;
			//_plugin_logprintf(module_name_str.c_str());

			if (is_jmp_instruction(basicinfo.instruction) && module_name_str == "unityplayer") {
				unsigned char nopChar = 0x90;
				// jmp地址未执行过
				if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == false) {
					// 记录jump地址所在位置
					duint jmpStartAddress = uiAddr;

					string temp_s = basicinfo.instruction;
					temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 3, ""); // 获取jmp指令使用的寄存器

					duint jmp_address = DbgValFromString(temp_s.c_str());  // 获取jmp指令跳转的地址
					_plugin_logprintf(u8"[反米哈游CFG混淆插件] [0x%p] : %s\n", uiAddr, basicinfo.instruction); //打印日志
					_plugin_logprintf(u8"[反米哈游CFG混淆插件] JMP指令跳转的地址 : 0x%p\n", jmp_address); //打印日志
					temp_list.append(temp_s);
					temp_list.append(jmp_address);

					Json::Value normal_instruction;

					// 获取上一条指令的开始地址
					duint temp_address = uiAddr;
					string x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
					DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
					temp_address = DbgValFromString(x64dbg_instruction.c_str());

					// 如果jmp指令上方不是add 则有正常指令
					if (!is_add_instruction(basicinfo.instruction)) {
						// 添加第一次搜索到的指令
						normal_instruction.append(basicinfo.instruction);

						// 加循环搜索正常指令
						while (true) {
							string x64dbg_instruction = "dis.next(0x" + DecIntToHexStr(temp_address) + ")";
							DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
							temp_address = DbgValFromString(x64dbg_instruction.c_str());

							if (is_add_instruction(basicinfo.instruction)) {
								break;
							}
							else {
								normal_instruction.append(basicinfo.instruction);
							}
						}
					}

					// 获取上一条指令的开始地址
					x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
					DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
					temp_address = DbgValFromString(x64dbg_instruction.c_str());


					// 从mov指令获取jmp指令相关的寄存器
					if (is_mov_instruction(basicinfo.instruction)) {
						smatch match;
						regex pattern_1("r[abcd][xi]\\*8"); // 跳转判断寄存器
						regex pattern_2("r[abcd][xi]");
						string str = basicinfo.instruction;

						regex_search(str, match, pattern_1);

						if (match.size() == 1) {
							string v2 = match[0].str();
							smatch match_2;
							regex_search(v2, match_2, pattern_2);
							v2 = match_2[0].str();
							duint mov_value = DbgValFromString(v2.c_str());  // 获取jmp指令相关的寄存器值
							temp_list.append(v2);
							temp_list.append(mov_value);
						}
					}
					// 获取上一条指令的开始地址
					x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
					DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
					temp_address = DbgValFromString(x64dbg_instruction.c_str());

					// 在lea指令处还原指令
					if (is_lea_instruction(basicinfo.instruction)) {

						// nop填充处理
						duint tempV1 = temp_address;
						while (true) {
							if (temp_address == jmpStartAddress)
								break;
							DbgMemWrite(temp_address, &nopChar, 1);
							temp_address += 1;
						}
						temp_address = tempV1;

						// jmp指令前无正常指令
						if (normal_instruction.empty()) {
							string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
							_plugin_logprintf(u8"[反米哈游CFG混淆插件] 将地址 0x%p 修改为正常jmp指令 %s \n", temp_address, instruction.c_str());
							DbgAssembleAt(temp_address, instruction.c_str());
						}
						// jmp指令前有正常指令
						else {
							int normal_instruction_size = normal_instruction.size();
							for (int i = 0; i < normal_instruction_size; ++i) {
								// 恢复正常指令
								string instruction = normal_instruction[i].asCString();
								_plugin_logprintf(u8"[反米哈游CFG混淆插件] 在地址 0x%p 恢复正常指令 %s\n", temp_address, instruction.c_str());
								DbgAssembleAt(temp_address, instruction.c_str());

								// 获取下一条指令开始地址
								x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
								DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
								temp_address = DbgValFromString(x64dbg_instruction.c_str());
							}

							string instruction = "jmp 0x" + DecIntToHexStr(jmp_address);
							_plugin_logprintf(u8"[反米哈游CFG混淆插件] 将地址 0x%p 修改为正常jmp指令 %s \n", temp_address, instruction.c_str());
							DbgAssembleAt(temp_address, instruction.c_str());
						}
						jmp_list[DecIntToHexStr(temp_address)] = temp_list;
						temp_list.clear();
					}
					DbgCmdExecDirect("StepOver");
					DbgMemWrite(jmpStartAddress, &nopChar, 1);
					DbgMemWrite(jmpStartAddress + 1, &nopChar, 1);

					GuiSelectionGet(GUI_DISASSEMBLY, &sel); //获取指定 GUI 视图的当前选定行（或多行）并将信息作为起始地址和结束地址返回到 SELECTIONDATA 变量中。
					temp_address = sel.start; //获取当前地址

					const std::regex pattern_jmp("jmp");
					// 在下一个jmp指令打断点
					while (true) {
						x64dbg_instruction = "dis.next(0x" + DecIntToHexStr(temp_address) + ")";
						DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
						temp_address = DbgValFromString(x64dbg_instruction.c_str());

						if (regex_match(basicinfo.instruction, pattern_jmp) && !is_jmp_instruction(basicinfo.instruction))
						{
							temp_s = basicinfo.instruction;
							temp_s = temp_s.replace(temp_s.begin(), temp_s.begin() + 4, "");
							temp_address = DbgValFromString(temp_s.c_str());
							_plugin_logprintf(basicinfo.instruction);
							continue;
						}

						if (is_jmp_instruction(basicinfo.instruction)) {
							x64dbg_instruction = "bp " + DecIntToHexStr(temp_address);
							DbgCmdExecDirect(x64dbg_instruction.c_str());
							break;
						}
					}
					DbgCmdExecDirect("run");
				}
			}
			else if (jmp_list.isMember(DecIntToHexStr(uiAddr)) == true && module_name_str == "unityplayer") { // 当jmp地址运行过了

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
					DbgCmdExecDirect("StepOver");
				}

				else {
					// 获取原先修改的jump地址
					string x64dbg_instruction = "dis.brtrue(0x" + DecIntToHexStr(uiAddr) + ")";
					DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
					duint old_jump_to_address = DbgValFromString(x64dbg_instruction.c_str());

					// 获取现在的jump地址
					duint new_jump_to_address = DbgValFromString(jmp_list[DecIntToHexStr(uiAddr)][0].asCString()); // jmp_list[DecIntToHexStr(uiAddr)][0] 为jmp指令所用寄存器

					// 当地址相同时 不进行操作
					if (old_jump_to_address == new_jump_to_address) {
						DbgCmdExecDirect("StepOver");
					}
					// 当地址不相同时 进行操作
					else {
						// 写入跳转指令
						string cmp_instruction = "cmp " + jmp_list[DecIntToHexStr(uiAddr)][2].asString() + "," + jmp_list[DecIntToHexStr(uiAddr)][3].asString();
						string je_instruction = "je 0x" + DecIntToHexStr(old_jump_to_address);
						string jmp_instruction = "jmp 0x" + DecIntToHexStr(new_jump_to_address);

						_plugin_logprintf(u8"[反米哈游CFG混淆插件] 在地址 0x%p 开始恢复跳转指令 \n", uiAddr);

						// 写入cmp指令
						duint temp_address = uiAddr;
						DbgAssembleAt(temp_address, cmp_instruction.c_str());

						// 获取下一条指令开始地址
						x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
						DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
						temp_address = DbgValFromString(x64dbg_instruction.c_str());

						// 写入je指令
						DbgAssembleAt(temp_address, je_instruction.c_str());

						// 获取下一条指令开始地址
						x64dbg_instruction = "dis.prev(0x" + DecIntToHexStr(temp_address) + ")";
						DbgDisasmFastAt(DbgValFromString(x64dbg_instruction.c_str()), &basicinfo);
						temp_address = DbgValFromString(x64dbg_instruction.c_str());

						// 写入jmp指令
						DbgAssembleAt(temp_address, jmp_instruction.c_str());

						DbgCmdExecDirect("StepOver");
					}
				}
			}
		}
	}
}


bool is_mov_instruction(const std::string& instruction) {
	//00007FFE7A635B0C | 48:8B04C1                | mov rax, qword ptr ds:[rcx+rax*8]        |
	const std::regex pattern("mov r\\w\\w, ds:\\[r\\w\\w\\+r\\w\\w\\*8\\]");
	if (std::regex_match(instruction, pattern)) {
		return 1;
	}
	else {
		const std::regex pattern("mov r\\w\\w, ds : \\[r\\w\\w \\+ r\\w\\w\\*8\\]");
		if (std::regex_match(instruction, pattern)) {
			return 1;
		}
		else {
			return 0;
		}
	}
}

bool is_add_instruction(const std::string& instruction) {
	const std::regex pattern("add r\\w\\w, 0xFFFFFFFF\\w\\w\\w\\w\\w\\w\\w\\w");
	return std::regex_match(instruction, pattern);
}

bool is_lea_instruction(const std::string& instruction) {
	const std::regex pattern("lea r\\w\\w, ds:\\[0x0000\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\w\\]");
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