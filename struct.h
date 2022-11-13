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

// 取模块名称结构体
typedef struct ModuleInfoStruct
{
	CHAR ModuleName[1024];
}ModuleInfoStruct, *LPModuleInfoStruct;
