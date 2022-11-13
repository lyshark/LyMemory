# LyMemory 驱动级内存读写

<br>

<div align=center>
 
![image](https://user-images.githubusercontent.com/52789403/201507004-5ebeaea5-022e-4bf5-865e-3632a144c9ab.png)

</div>

<br>

一款完全免费的内核级内存读写工具，可强制读写任意应用层进程内存数据，驱动工具目前支持读写整数，字节，字节集，单精度浮点数，双精度浮点数，多级偏移读写，取模块地址，分配远程内存等功能，读写效率高，速度快，兼容性好，稳定不拉闸，使用时需自己签名或在测试模式下。

 - 警告: 请勿用于非法用途，本工具只是Demo演示项目，上号很容易拉闸，谨慎使用！
   - 问：你这个东西是什么读写原理？ 答：目前支持物理页，CR3，内存拷贝，MDL(默认)
   - 问：你这个东西会拉闸吗？ 答：会，拉闸的速度取决于你读写的是什么游戏。
   - 问：拉闸后我该怎么办？答：等着封号10年，另起炉灶！

程序调用次序如下：

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/201503404-aa2cef29-8659-4c06-8894-17def747d064.png)

</div>

<br>

无论是非持续读写还是持续读写，安装驱动都是必须要做的，如下将演示如何调用`Engine.dll`模块实现对`LyMemory.sys`驱动的安装与卸载，当然这一步并不是必须的，你也可以通过第三方工具将驱动安装并运行起来。
```c
#include <iostream>
#include <Windows.h>

// 定义安装与卸载驱动
typedef void(*InstallDriver)();
typedef void(*RemoveDriver)();

int main(int argc, char *argv[])
{
	// 动态加载
	HMODULE hmod = LoadLibrary(L"Engine32.dll");

	// 获取到函数地址
	InstallDriver InstallDrivers = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	RemoveDriver RemoveDrivers = (RemoveDriver)GetProcAddress(hmod, "RemoveDriver");
	
	// 安装驱动
	InstallDrivers();

	Sleep(5000);

	// 卸载驱动
	RemoveDrivers();
	
	return 0;
}
```

<br>

### 非持续读写

读写时需要传入进程PID以及读写地址，此类读写方式适合非持续访问，常用于一次性改写，一次性读取的场景，目前非持续读写包括了如下20个读写子功能。

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

<br>

### 持续读写

读写时需要提前设置进程PID号，后期的调用将不需要再传入进程PID号，此类读写适合长期读，某些参数例如人物数组，坐标等，需要持续不间断读取。

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

<br>

### 案例演示

**内存读写字节:** 以内存读取作为第一个演示对象，动态调用`ReadProcessMemoryByte`可以这样来写，首先定义`typedef`动态指针，并通过`GetProcAddress`函数得到内存地址，最后调用指针`read_process_memory_byte`实现读取内存字节的功能。
```c
#include <iostream>
#include <Windows.h>

// 定义安装与卸载驱动
typedef void(*InstallDriver)();
typedef void(*RemoveDriver)();

// 读内存字节
typedef BYTE(*ReadProcessMemoryByte)(DWORD pid, ULONG64 address);

int main(int argc, char *argv[])
{
	// 动态加载驱动
	HMODULE hmod = LoadLibrary(L"Engine32.dll");

	InstallDriver InstallDrivers = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	RemoveDriver RemoveDrivers = (RemoveDriver)GetProcAddress(hmod, "RemoveDriver");

	InstallDrivers();

	// 得到内存地址
	ReadProcessMemoryByte read_process_memory_byte = \
		(ReadProcessMemoryByte)GetProcAddress(hmod, "ReadProcessMemoryByte");

	// 调用得到数据
	BYTE ref = read_process_memory_byte(6764, 0x0057e070);

	printf("输出数据：%x | 十进制：%d \n", ref, ref);

	getchar();
	RemoveDrivers();
	return 0;
}
```
运行这段代码，即可得到进程PID为`6764`地址`0x0057e070`处一个字节的数据，如下所示；

![image](https://user-images.githubusercontent.com/52789403/201504131-e53d0ee3-dc1b-48ba-bdfc-6428e793fcb5.png)

**内存字节反汇编:** 读内存字节功能不仅可以用于读取内存中的数值，配合`capstone`反汇编引擎可以实现对特定区域的反汇编。
```c
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <inttypes.h>
#include <capstone\capstone.h>

#pragma comment(lib,"capstone32.lib")

// 定义安装与卸载驱动
typedef void(*InstallDriver)();
typedef void(*RemoveDriver)();

// 读内存字节
typedef BYTE(*ReadProcessMemoryByte)(DWORD pid, ULONG64 address);

int main(int argc, char *argv[])
{
	// 动态加载驱动
	HMODULE hmod = LoadLibrary(L"Engine32.dll");

	InstallDriver InstallDrivers = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	RemoveDriver RemoveDrivers = (RemoveDriver)GetProcAddress(hmod, "RemoveDriver");

	InstallDrivers();

	// 得到内存地址
	ReadProcessMemoryByte read_process_memory_byte = \
		(ReadProcessMemoryByte)GetProcAddress(hmod, "ReadProcessMemoryByte");


	BYTE arr[1024] = { 0 };

	for (size_t i = 0; i < 1023; i++)
	{
		BYTE by = read_process_memory_byte(6764, 0x005800b8 + i);

		arr[i] = by;
	}

	csh handle;
	cs_insn *insn;
	size_t count;

	int size = 1023;

	// 打开句柄
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	{
		return 0;
	}

	// 反汇编代码,地址从0x1000开始,返回总条数
	count = cs_disasm(handle, (unsigned char *)arr, size, 0x402c00, 0, &insn);

	if (count > 0)
	{
		size_t index;
		for (index = 0; index < count; index++)
		{
			for (int x = 0; x < insn[index].size; x++)
			{
				// printf("机器码: %d -> %02X \n", x, insn[index].bytes[x]);
			}

			printf("地址: 0x%"PRIx64" | 长度: %d 反汇编: %s %s \n", \
			insn[index].address, insn[index].size, insn[index].mnemonic, insn[index].op_str);
		}

		cs_free(insn, count);
	}
	else
	{
		printf("反汇编返回长度为空 \n");
	}

	cs_close(&handle);

	getchar();
	RemoveDrivers();
	return 0;
}
```
如上代码我们反汇编进程内`0x005800b8`地址，向下反汇编`1024`字节，输出反汇编效果如下；

![image](https://user-images.githubusercontent.com/52789403/201504316-bac89189-eeb1-4b71-9805-7819d5f65e0a.png)

**读写多级指针:** 读取整数浮点数与读字节一致这里不再演示了，重点看下多级偏移如何读写，读取多级偏移需要动态调用`ReadProcessDeviationInt32`函数。
```C
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <inttypes.h>

// 定义安装与卸载驱动
typedef void(*InstallDriver)();
typedef void(*RemoveDriver)();

// 读写内存偏移整数型
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	INT64 data;
}ProcessDeviationIntMemory;

// 定义指针
typedef INT32(*ReadProcessDeviationInt32)(ProcessDeviationIntMemory);

int main(int argc, char *argv[])
{
	// 动态加载驱动
	HMODULE hmod = LoadLibrary(L"Engine32.dll");

	InstallDriver InstallDrivers = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	RemoveDriver RemoveDrivers = (RemoveDriver)GetProcAddress(hmod, "RemoveDriver");

	InstallDrivers();

	// 读取多级偏移整数型
	ReadProcessDeviationInt32 read_process_deviation_int32 = (ReadProcessDeviationInt32) \
		GetProcAddress(hmod, "ReadProcessDeviationInt32");

	ProcessDeviationIntMemory read_memory = { 0 };

	read_memory.pid = 6764;                  // 进程PID
	read_memory.base_address = 0x6566e0;     // 基地址
	read_memory.offset_len = 4;              // 偏移长度
	read_memory.data = 0;                    // 读入的数据
	read_memory.offset[0] = 0x18;            // 一级偏移
	read_memory.offset[1] = 0x0;             // 二级偏移
	read_memory.offset[2] = 0x14;            // 三级偏移
	read_memory.offset[3] = 0x0c;            // 四级偏移

	DWORD ref = read_process_deviation_int32(read_memory);

	printf("读取参数: %d \n", ref);

	getchar();
	RemoveDrivers();
	return 0;
}
```

读取多级偏移效果如下：

![image](https://user-images.githubusercontent.com/52789403/192539232-56aa1e34-d113-4625-ac9b-226b6f8cb0cc.png)

**内核读取模块基地址：** 内核中强制读取指定进程中模块的基地址。
```c
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <inttypes.h>

// 定义安装与卸载驱动
typedef void(*InstallDriver)();
typedef void(*RemoveDriver)();

typedef DWORD64 (*GetModuleAddress)(DWORD pid, std::string dllname);

int main(int argc, char *argv[])
{
	// 动态加载驱动
	HMODULE hmod = LoadLibrary(L"Engine32.dll");

	InstallDriver InstallDrivers = (InstallDriver)GetProcAddress(hmod, "InstallDriver");
	RemoveDriver RemoveDrivers = (RemoveDriver)GetProcAddress(hmod, "RemoveDriver");

	InstallDrivers();

	// 读取模块基址
	GetModuleAddress get_module_address = (GetModuleAddress)GetProcAddress(hmod, "GetModuleAddress");

	// 调用
	DWORD64 address = get_module_address(6764, "user32.dll");
	printf("dllbase = 0x%016I64x \n", address);

	getchar();
	RemoveDrivers();
	return 0;
}
```

以`user32.dll`模块为例，读取效果如下所示；

![image](https://user-images.githubusercontent.com/52789403/201504971-f7aa9578-8b23-4d2f-b322-1f057b9d9a0b.png)

<br>

GitHub 项目地址: https://github.com/lyshark/LyMemory
