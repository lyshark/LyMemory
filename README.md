# LyMemory 驱动级内存读写

<br>

<div align=center>
 
![image](https://user-images.githubusercontent.com/52789403/192542155-051f469a-e01d-432d-8e2e-e62e2d39bbc8.png)
 
</div>

<br>

一款内核级读写工具，可强制读写任意应用层进程内存数据，用于突破游戏驱动保护强行读写对端内存，驱动工具目前支持读写整数，字节，字节集，单精度浮点数，双精度浮点数，多级偏移读写等功能，读写效率高，使用需自己签名或在测试模式。

<b>声明：为保护代码不泛滥，目前不开源，当关注数量提升到一定程度一定会开源，感谢支持与理解！</b>

程序调用次序如下：

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/192541072-4dfa14e5-046f-41d5-bcc4-4ed04d58b316.png)

</div>

读写工具目前支持的读写模式包括通用读写函数:

|  导出函数   | 函数作用  |
|  ----  | ----  |
| BYTE ReadProcessMemoryByte(DWORD Pid, ULONG64 Address) | 读内存字节 |
| BOOL WriteProcessMemoryByte(DWORD Pid, ULONG64 Address, BYTE bytef) | 写内存字节 |
| DWORD ReadProcessMemoryInt32(DWORD Pid, ULONG64 Address) | 读内存32位整数型 |
| DWORD ReadProcessMemoryInt64(DWORD Pid, ULONG64 Address) | 读内存64位整数型 |
| BOOL WriteProcessMemoryInt32(DWORD Pid, ULONG64 Address, DWORD write) | 写内存32位整数型 |
| BOOL WriteProcessMemoryInt64(DWORD Pid, ULONG64 Address, DWORD write) | 写内存64位整数型 |
| FLOAT ReadProcessMemoryFloat(DWORD Pid, ULONG64 Address) | 读内存单精度浮点数 |
| DOUBLE ReadProcessMemoryDouble(DWORD Pid, ULONG64 Address) | 读内存双精度浮点数 |
| BOOL WriteProcessMemoryFloat(DWORD Pid, ULONG64 Address, FLOAT write) | 写内存单精度浮点数 |
| BOOL WriteProcessMemoryDouble(DWORD Pid, ULONG64 Address, DOUBLE write) | 写内存双精度浮点数 |
| INT32 ReadProcessDeviationInt32(ProcessDeviationIntMemory *read_offset_struct) | 读多级偏移32位整数 |
| INT64 ReadProcessDeviationInt64(ProcessDeviationIntMemory *read_offset_struct) | 读多级偏移64位整数 |
| BOOL WriteProcessDeviationInt32(ProcessDeviationIntMemory *write_offset_struct) | 写多级偏移32位整数 |
| BOOL WriteProcessDeviationInt64(ProcessDeviationIntMemory *write_offset_struct) | 写多级偏移64位整数 |
| DWORD ReadDeviationMemory32(ProcessDeviationMemory *read_offset_struct) | 读多级偏移32位内存 |
| DWORD64 ReadDeviationMemory64(ProcessDeviationMemory *read_offset_struct) | 读多级偏移64位内存 |
| BYTE ReadDeviationByte(ProcessDeviationMemory *read_offset_struct) | 读多级偏移字节型 |
| FLOAT ReadDeviationFloat(ProcessDeviationMemory *read_offset_struct) | 读多级偏移单浮点数 |
| BOOL WriteDeviationByte(ProcessDeviationMemory *write_offset_struct,BYTE write_byte) | 写多级偏移字节型 |
| BOOL WriteDeviationFloat(ProcessDeviationMemory *write_offset_struct,FLOAT write_float) | 写多级偏移单浮点数 |

以及全局读写函数：

|  导出函数   | 函数作用  |
|  ----  | ----  |
| BOOL SetPid(DWORD Pid) | 设置全局进程PID |
| BOOL Read(DWORD pid, ULONG64 address, T* ret) | 全局读内存 |
| BOOL Write(DWORD pid, ULONG64 address, T data) | 全局写内存 |
| void ReadMemoryDWORD(DWORD pid, ULONG64 addre, DWORD * ret) | 读内存DWORD |
| void ReadMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 * ret) | 读内存DWORD64 |
| void ReadMemoryBytes(DWORD pid, ULONG64 addre, BYTE **ret, DWORD sizes) | 读内存字节 |
| void ReadMemoryFloat(DWORD pid, ULONG64 addre, float* ret) | 读内存浮点数 |
| void ReadMemoryDouble(DWORD pid, ULONG64 addre, double* ret) | 读内存双精度浮点数 |
| void WriteMemoryBytes(DWORD pid, ULONG64 addre, BYTE * data, DWORD sizes) | 写内存字节 |
| void WriteMemoryDWORD(DWORD pid, ULONG64 addre, DWORD ret) | 写内存DWORD |
| void WriteMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 ret) | 写内存DWORD64 |
| void WriteMemoryFloat(DWORD pid, ULONG64 addre, float ret) | 写内存浮点数 |
| void WriteMemoryDouble(DWORD pid, ULONG64 addre, double ret) | 写内存双精度浮点数 |
| DWORD64 GetModuleAddress(DWORD pid, std::string dllname) | 驱动读取进程模块基地址 |
| DWORD GetProcessID(std::string procname) | 根据进程名称获取进程PID |
| DWORD64 GetSystemRoutineAddress(std::string funcname) | 获取系统函数内存地址 |
| DWORD64 CreateRemoteMemory(DWORD length) | 在对端分配内存空间 |
| DWORD DeleteRemoteMemory(DWORD64 address, DWORD length) | 销毁对端内存 |

以读取多级偏移为例，需要动态调用`Engine.dll`里面的导出函数，由导出函数去调用`LyMemory.sys`驱动程序，获取结果。
```C
#include <iostream>
#include <Windows.h>

// 安装驱动
typedef void(*InstallDriver)();

// 读写内存偏移整数型
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	INT64 data;
}ProcessDeviationIntMemory;

typedef INT32(*ReadProcessDeviationInt32)(ProcessDeviationIntMemory);

int main(int argc, char *argv[])
{
	// 动态加载驱动
	HMODULE hmod = LoadLibrary(L"Engine.dll");

	InstallDriver Install = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	Install();

	// 读取多级偏移整数型
	ReadProcessDeviationInt32 read = (ReadProcessDeviationInt32) \
	                            GetProcAddress(hmod, "ReadProcessDeviationInt32");
	
	ProcessDeviationIntMemory write = { 0 };

	write.pid = 6672;                  // 进程PID
	write.base_address = 0x6566e0;     // 基地址
	write.offset_len = 4;              // 偏移长度
	write.data = 0;                    // 读入的数据
	write.offset[0] = 0x18;            // 一级偏移
	write.offset[1] = 0x0;             // 二级偏移
	write.offset[2] = 0x14;            // 三级偏移
	write.offset[3] = 0x0c;            // 四级偏移

	DWORD ref = read(write);

	printf("读取参数: %d \n", ref);

	getchar();
	return 0;
}
```

读取多级偏移效果如下：

![image](https://user-images.githubusercontent.com/52789403/192539232-56aa1e34-d113-4625-ac9b-226b6f8cb0cc.png)
