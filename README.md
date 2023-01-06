# 内核级内存读写驱动

<br>

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/210537145-bbf8cc74-64e7-4477-bafd-109437de6131.png)

</div>

<br>

<div align=center>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/LyMemory) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![OSCS Status](https://cdn.lyshark.com/archive/LyScript/OSCS.svg)](https://www.oscs1024.com/project/lyshark/LyMemory?ref=badge_small)

</div>

<br>

一款完全免费的内核级内存读写工具，可突破驱动保护，强制读写应用层任意进程内存数据，驱动工具目前支持读写整数，字节，字节集，单精度浮点数，双精度浮点数，多级偏移读写，取模块地址，分配远程内存等功能，读写效率高，速度快，兼容性好，使用时需自己签名或在测试模式下。


**新版本更新中，包括功能，驱动注入，驱动鼠标键盘控制，将解决更多潜在问题，提供lib库文件。**

 - 请勿用于非法用途，本工具只是演示项目，上号很容易拉闸，谨慎使用！
   - 问：你这个东西是什么读写原理？ 答：目前支持物理页，CR3，内存拷贝，MDL(默认)
   - 问：你这个东西会拉闸吗？ 答：会，拉闸的速度取决于你读写的是什么游戏。
   - 问：拉闸后我该怎么办？答：等着封号10年，建议另起炉灶！

作者警告，该项目仅用于测试与安全技术交流，禁止用于非法读写网络游戏，本人不承担任何法律责任，另外不要拿我的驱动和商业驱动相比，毕竟那个是按天收费的，我是无私奉献只为交个朋友点个start，请勿对我的作品二次包装出售。

<br>

## 读写函数预览

非持续读写函数，读写时需要传入进程PID以及读写地址，此类读写方式适合非持续访问，常用于一次性改写，一次性读取的场景，目前非持续读写包括了如下20个读写子功能。

|  导出函数   | 函数作用  |
|  ----  | ----  |
| BOOL SwitchDriver(PCHAR pSwitchName) | 切换读写模式 |
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

持续读写函数，读写时需要提前设置进程PID号，后期的调用将不需要再传入进程PID号，此类读写适合长期读，某些参数例如人物数组，坐标等，需要持续不间断读取。

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

## 动态调用驱动

驱动读写目前支持两种调用模式，使用`Engine.dll`模块可动态调用驱动功能，如下图所示，如果用户采用动态调用模式则需要首先使用`LoadLibrary`加载该引擎，通过`GetProcAddress`函数拿到内存指针，之后才能调用功能。

<div align=center>

![image](https://user-images.githubusercontent.com/52789403/201503404-aa2cef29-8659-4c06-8894-17def747d064.png)

</div>

项目中的`dllexport.h`以及`struct.h`是用于参考的调用函数定义，为了能直观的演示功能，我们以内核读取模块基地址，内存读写字节，内存字节反汇编，读写多级指针，四个功能作为演示，以让用户能够更好的理解。

在开始之前安装驱动都是必须要做的，通过调用`Engine.dll`模块实现对`LyMemory.sys`驱动的安装与卸载很容易，如下代码即可实现动态加载。
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

<br>

## 静态库调用驱动

与动态调用相比，静态库则需要在编程时使用特定的库文件，目前`LyMemory`只提供了`64`位库文件，编译程序时也必须使用`x64`模式，使用时需要手动引用到项目内，至于如何引用到项目中此处就不再赘述了。

相比于动态加载来说，静态库调用就方便了许多，一般可以直接使用如下的方式实现调用。
```c
#include <LyMemoryLib.h>

#pragma comment(lib,"LyMemoryLib.lib")

int main(int argc, char* argv[])
{
	LyMemoryDrvCtrl Memory;

	char szSysFile[MAX_PATH] = { 0 };
	char szSvcLnkName[] = "LyMemory";;
	BOOL ref = FALSE;

	// 获取完整路径
	Memory.GetAppPath(szSysFile);
	strcat(szSysFile, "LyMemory.sys");
	printf("路径: %s \n", szSysFile);

	// 安装驱动
	ref = Memory.Install(szSysFile, szSvcLnkName, szSvcLnkName);
	printf("状态: %d \n", ref);

	// 启动驱动
	ref = Memory.Start();
	printf("状态: %d \n", ref);

	ref = Memory.Open("\\\\.\\LyMemory");
	printf("状态: %d \n", ref);

	// 关闭移除驱动
	ref = Memory.Stop();
	ref = Memory.Remove();
	printf("状态: %d \n", ref);

	getchar();
	return 0;
}
```

程序运行后则会输出驱动具体路径以及安装状态，安装成功即可看到打印信息。

![image](https://user-images.githubusercontent.com/52789403/210949244-26fb4130-7532-4264-80e7-8d6a987d9a2b.png)








<br><br>


<br>

## 项目地址

https://github.com/lyshark/LyMemory
