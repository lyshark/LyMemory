#pragma once
#ifndef LyMemoryLib__h
#define LyMemoryLib__h
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")

// ------------------------------------------------------------------------------
// 内存读写结构定义
// ------------------------------------------------------------------------------

// 读写内存整数结构体
typedef struct
{
	DWORD pid;
	ULONG64 address;
	UINT bytes_toread;
	DWORD64 data;
}ProcessIntMemory;

// 读写内存偏移整数型
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	INT64 data;
}ProcessDeviationIntMemory;

// 读写多级偏移内存地址
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	DWORD64 data;
}ProcessDeviationMemory;

// 读写内存字节型
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	BYTE OpCode;
}ProcessByteMemory;

// 附加通用读写
typedef struct r3Buffer
{
	ULONG64 Address;
	ULONG64 Buffer;
	ULONG64 size;
}appBuffer;

// 取模块名称结构体
typedef struct ModuleInfoStruct
{
	CHAR ModuleName[1024];
}ModuleInfoStruct, *LPModuleInfoStruct;

// ------------------------------------------------------------------------------
// 定义驱动功能号和名字，提供接口给应用程序调用
// ------------------------------------------------------------------------------

// 通用读写系列
#define IOCTL_IO_ReadProcessMemory        0x801
#define IOCTL_IO_WriteProcessMemory       0x802
#define IOCTL_IO_ReadDeviationIntMemory   0x803
#define IOCTL_IO_WriteDeviationIntMemory  0x804
#define IOCTL_IO_ReadProcessMemoryByte    0x805
#define IOCTL_IO_WriteProcessMemoryByte   0x806

// 全局读写系列
#define IOCTL_IO_SetPID                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_ReadMemory               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_WriteMemory              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 模块操作系列
#define IOCTL_IO_GetModuleAddress         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_GetProcessID             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_GetSystemRoutineAddr     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_CreateAllocMemory        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_RemoveAllocMemory        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 版本升级后的新功能 2022-09-24
#define IOCTL_IO_ReadDeviationMemory    0x815

// ------------------------------------------------------------------------------
// 驱动控制类
// ------------------------------------------------------------------------------

class __declspec(dllexport) LyMemoryDrvCtrl
{
	// ------------------------------------------------------------------
	// 通用函数封装
	// ------------------------------------------------------------------
public:
	LyMemoryDrvCtrl();
	~LyMemoryDrvCtrl();

	// 安装驱动
	BOOL Install(PCHAR pSysPath, PCHAR pServiceName, PCHAR pDisplayName);

	// 启动驱动
	BOOL Start();

	// 关闭驱动
	BOOL Stop();

	// 移除驱动
	BOOL Remove();

	// 打开驱动
	BOOL Open(PCHAR pLinkName);

	// 切换读写模式
	BOOL SwitchDriver(PCHAR pSwitchName);

	// 发送控制信号
	BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);

	// ------------------------------------------------------------------
	// 通用独立读写函数
	// ------------------------------------------------------------------

	// 读内存字节
	BYTE ReadProcessMemoryByte(DWORD Pid, ULONG64 Address);

	// 写内存字节
	BOOL WriteProcessMemoryByte(DWORD Pid, ULONG64 Address, BYTE bytef);

	// 读内存32位整数型
	DWORD ReadProcessMemoryInt32(DWORD Pid, ULONG64 Address);

	// 读内存64位整数型
	DWORD ReadProcessMemoryInt64(DWORD Pid, ULONG64 Address);

	// 写内存32位整数型
	BOOL WriteProcessMemoryInt32(DWORD Pid, ULONG64 Address, DWORD write);

	// 写内存64位整数型
	BOOL WriteProcessMemoryInt64(DWORD Pid, ULONG64 Address, DWORD write);

	// 读内存单精度浮点数
	FLOAT ReadProcessMemoryFloat(DWORD Pid, ULONG64 Address);

	// 读内存双精度浮点数
	DOUBLE ReadProcessMemoryDouble(DWORD Pid, ULONG64 Address);

	// 写内存单精度浮点数
	BOOL WriteProcessMemoryFloat(DWORD Pid, ULONG64 Address, FLOAT write);

	// 写内存双精度浮点数
	BOOL WriteProcessMemoryDouble(DWORD Pid, ULONG64 Address, DOUBLE write);

	// 读多级偏移32位整数型
	INT32 ReadProcessDeviationInt32(ProcessDeviationIntMemory *read_offset_struct);

	// 读多级偏移64位整数型
	INT64 ReadProcessDeviationInt64(ProcessDeviationIntMemory *read_offset_struct);

	// 写多级偏移32位整数型
	BOOL WriteProcessDeviationInt32(ProcessDeviationIntMemory *write_offset_struct);

	// 写多级偏移64位整数型
	BOOL WriteProcessDeviationInt64(ProcessDeviationIntMemory *write_offset_struct);

	// 读多级偏移32位内存地址
	DWORD ReadDeviationMemory32(ProcessDeviationMemory *read_offset_struct);

	// 读多级偏移64位内存地址
	DWORD64 ReadDeviationMemory64(ProcessDeviationMemory *read_offset_struct);

	// 读多级偏移字节型
	BYTE ReadDeviationByte(ProcessDeviationMemory *read_offset_struct);

	// 读多级偏移单精度浮点数
	FLOAT ReadDeviationFloat(ProcessDeviationMemory *read_offset_struct);

	// 写多级偏移字节型
	BOOL WriteDeviationByte(ProcessDeviationMemory *write_offset_struct, BYTE write_byte);

	// 写多级偏移单精度浮点数
	BOOL WriteDeviationFloat(ProcessDeviationMemory *write_offset_struct, FLOAT write_float);

	// ------------------------------------------------------------------
	// 全局内存读写系列函数
	// ------------------------------------------------------------------

	// 设置全局进程PID
	BOOL SetPid(DWORD Pid);

	// 全局读内存
	template <typename T>
	BOOL Read(DWORD pid, ULONG64 address, T* ret);

	// 全局写内存
	template <typename T>
	BOOL Write(DWORD pid, ULONG64 address, T data);

	// 读内存DWORD
	VOID ReadMemoryDWORD(DWORD pid, ULONG64 addre, DWORD * ret);

	// 读内存DWORD64
	VOID ReadMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 * ret);

	// 读内存字节
	VOID ReadMemoryBytes(DWORD pid, ULONG64 addre, BYTE **ret, DWORD sizes);

	// 读内存浮点数
	VOID ReadMemoryFloat(DWORD pid, ULONG64 addre, float* ret);

	// 读内存双精度浮点数
	VOID ReadMemoryDouble(DWORD pid, ULONG64 addre, double* ret);

	// 写内存字节
	VOID WriteMemoryBytes(DWORD pid, ULONG64 addre, BYTE * data, DWORD sizes);

	// 写内存DWORD
	VOID WriteMemoryDWORD(DWORD pid, ULONG64 addre, DWORD ret);

	// 写内存DWORD64
	VOID WriteMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 ret);

	// 写内存浮点数
	VOID WriteMemoryFloat(DWORD pid, ULONG64 addre, float ret);

	// 写内存双精度浮点数
	VOID WriteMemoryDouble(DWORD pid, ULONG64 addre, double ret);

	// 驱动读取进程模块基地址
	DWORD64 GetModuleAddress(DWORD pid, std::string dllname);

	// 根据进程名称获取进程PID
	DWORD GetProcessID(std::string procname);

	// 获取系统函数内存地址
	DWORD64 GetSystemRoutineAddress(std::string funcname);

	// 在对端分配内存空间
	DWORD64 CreateRemoteMemory(DWORD length);

	// 销毁对端内存
	DWORD DeleteRemoteMemory(DWORD64 address, DWORD length);

	// ------------------------------------------------------------------
	// 私有属性与函数
	// ------------------------------------------------------------------
public:
	// 获取服务句柄
	BOOL GetSvcHandle(PCHAR pServiceName);

	// 获取控制信号对应字符串
	DWORD CTL_CODE_GEN(DWORD lngFunction);

	// 获取完整路径
	VOID GetAppPath(char *szCurFile);

	VOID dtoc(double dvalue, unsigned char* arr);

	VOID ftoc(float fvalue, unsigned char* arr);
public:
	DWORD m_dwLastError;
	PCHAR m_pSysPath;
	PCHAR m_pServiceName;
	PCHAR m_pDisplayName;
	HANDLE m_hDriver;
	SC_HANDLE m_hSCManager;
	SC_HANDLE m_hService;
};

#endif LyMemoryLib__h