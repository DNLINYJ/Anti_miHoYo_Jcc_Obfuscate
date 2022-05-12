# 原神1.4.51 反JMP(基本块分割) X64DBG 插件

原神1.4.51 反JMP(基本块分割) X64DBG插件

# 因时间及技术水平（汇编分析）问题 该项目已归档

> 函数功能

> void get_obfuscated_address_offset() // 获取JMP指令跳转的地址 并将JMP指令的跳转地址尝试自动修改为正确地址

> void is_xxx_instruction(const std::string& instruction) // 通过正则表达式匹配含有特征的汇编指令

> string DecIntToHexStr(long long num) // 将10进制字符串转为16进制字符串

>> 所需参数 num 10进制字符串
