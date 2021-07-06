# 原神1.4.51 反JMP(基本块分割) X64DBG 插件

原神1.4.51 反JMP(基本块分割) X64DBG 插件

> 函数功能

> void get_obfuscated_address_offset() // 获取JMP指令跳转的地址并将跳转地址的偏移量发送至Python WEB服务器

> void* SetBreakpoint_And_Fuck_JMP(void* args) // 设置JMP指令地址的断点，线程引用函数

> datas* get_jmp_address(int v1) // 从存放JMP指令的JSON文件中提取出JMP指令的偏移量 

>> 所需参数 v1 JMP指令在JSON文件中的位置

> string DecIntToHexStr(long long num) // 将10进制字符串转为16进制字符串

>> 所需参数 num 10进制字符串
