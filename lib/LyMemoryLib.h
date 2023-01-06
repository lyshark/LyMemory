#pragma once
#ifndef LyMemoryLib__h
#define LyMemoryLib__h
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")

// ------------------------------------------------------------------------------
// �ڴ��д�ṹ����
// ------------------------------------------------------------------------------

// ��д�ڴ������ṹ��
typedef struct
{
	DWORD pid;
	ULONG64 address;
	UINT bytes_toread;
	DWORD64 data;
}ProcessIntMemory;

// ��д�ڴ�ƫ��������
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	INT64 data;
}ProcessDeviationIntMemory;

// ��д�༶ƫ���ڴ��ַ
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	DWORD offset[32];
	DWORD offset_len;
	DWORD64 data;
}ProcessDeviationMemory;

// ��д�ڴ��ֽ���
typedef struct
{
	DWORD pid;
	ULONG64 base_address;
	BYTE OpCode;
}ProcessByteMemory;

// ����ͨ�ö�д
typedef struct r3Buffer
{
	ULONG64 Address;
	ULONG64 Buffer;
	ULONG64 size;
}appBuffer;

// ȡģ�����ƽṹ��
typedef struct ModuleInfoStruct
{
	CHAR ModuleName[1024];
}ModuleInfoStruct, *LPModuleInfoStruct;

// ------------------------------------------------------------------------------
// �����������ܺź����֣��ṩ�ӿڸ�Ӧ�ó������
// ------------------------------------------------------------------------------

// ͨ�ö�дϵ��
#define IOCTL_IO_ReadProcessMemory        0x801
#define IOCTL_IO_WriteProcessMemory       0x802
#define IOCTL_IO_ReadDeviationIntMemory   0x803
#define IOCTL_IO_WriteDeviationIntMemory  0x804
#define IOCTL_IO_ReadProcessMemoryByte    0x805
#define IOCTL_IO_WriteProcessMemoryByte   0x806

// ȫ�ֶ�дϵ��
#define IOCTL_IO_SetPID                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_ReadMemory               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_WriteMemory              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ģ�����ϵ��
#define IOCTL_IO_GetModuleAddress         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_GetProcessID             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_GetSystemRoutineAddr     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_CreateAllocMemory        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_RemoveAllocMemory        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

// �汾��������¹��� 2022-09-24
#define IOCTL_IO_ReadDeviationMemory    0x815

// ------------------------------------------------------------------------------
// ����������
// ------------------------------------------------------------------------------

class __declspec(dllexport) LyMemoryDrvCtrl
{
	// ------------------------------------------------------------------
	// ͨ�ú�����װ
	// ------------------------------------------------------------------
public:
	LyMemoryDrvCtrl();
	~LyMemoryDrvCtrl();

	// ��װ����
	BOOL Install(PCHAR pSysPath, PCHAR pServiceName, PCHAR pDisplayName);

	// ��������
	BOOL Start();

	// �ر�����
	BOOL Stop();

	// �Ƴ�����
	BOOL Remove();

	// ������
	BOOL Open(PCHAR pLinkName);

	// �л���дģʽ
	BOOL SwitchDriver(PCHAR pSwitchName);

	// ���Ϳ����ź�
	BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);

	// ------------------------------------------------------------------
	// ͨ�ö�����д����
	// ------------------------------------------------------------------

	// ���ڴ��ֽ�
	BYTE ReadProcessMemoryByte(DWORD Pid, ULONG64 Address);

	// д�ڴ��ֽ�
	BOOL WriteProcessMemoryByte(DWORD Pid, ULONG64 Address, BYTE bytef);

	// ���ڴ�32λ������
	DWORD ReadProcessMemoryInt32(DWORD Pid, ULONG64 Address);

	// ���ڴ�64λ������
	DWORD ReadProcessMemoryInt64(DWORD Pid, ULONG64 Address);

	// д�ڴ�32λ������
	BOOL WriteProcessMemoryInt32(DWORD Pid, ULONG64 Address, DWORD write);

	// д�ڴ�64λ������
	BOOL WriteProcessMemoryInt64(DWORD Pid, ULONG64 Address, DWORD write);

	// ���ڴ浥���ȸ�����
	FLOAT ReadProcessMemoryFloat(DWORD Pid, ULONG64 Address);

	// ���ڴ�˫���ȸ�����
	DOUBLE ReadProcessMemoryDouble(DWORD Pid, ULONG64 Address);

	// д�ڴ浥���ȸ�����
	BOOL WriteProcessMemoryFloat(DWORD Pid, ULONG64 Address, FLOAT write);

	// д�ڴ�˫���ȸ�����
	BOOL WriteProcessMemoryDouble(DWORD Pid, ULONG64 Address, DOUBLE write);

	// ���༶ƫ��32λ������
	INT32 ReadProcessDeviationInt32(ProcessDeviationIntMemory *read_offset_struct);

	// ���༶ƫ��64λ������
	INT64 ReadProcessDeviationInt64(ProcessDeviationIntMemory *read_offset_struct);

	// д�༶ƫ��32λ������
	BOOL WriteProcessDeviationInt32(ProcessDeviationIntMemory *write_offset_struct);

	// д�༶ƫ��64λ������
	BOOL WriteProcessDeviationInt64(ProcessDeviationIntMemory *write_offset_struct);

	// ���༶ƫ��32λ�ڴ��ַ
	DWORD ReadDeviationMemory32(ProcessDeviationMemory *read_offset_struct);

	// ���༶ƫ��64λ�ڴ��ַ
	DWORD64 ReadDeviationMemory64(ProcessDeviationMemory *read_offset_struct);

	// ���༶ƫ���ֽ���
	BYTE ReadDeviationByte(ProcessDeviationMemory *read_offset_struct);

	// ���༶ƫ�Ƶ����ȸ�����
	FLOAT ReadDeviationFloat(ProcessDeviationMemory *read_offset_struct);

	// д�༶ƫ���ֽ���
	BOOL WriteDeviationByte(ProcessDeviationMemory *write_offset_struct, BYTE write_byte);

	// д�༶ƫ�Ƶ����ȸ�����
	BOOL WriteDeviationFloat(ProcessDeviationMemory *write_offset_struct, FLOAT write_float);

	// ------------------------------------------------------------------
	// ȫ���ڴ��дϵ�к���
	// ------------------------------------------------------------------

	// ����ȫ�ֽ���PID
	BOOL SetPid(DWORD Pid);

	// ȫ�ֶ��ڴ�
	template <typename T>
	BOOL Read(DWORD pid, ULONG64 address, T* ret);

	// ȫ��д�ڴ�
	template <typename T>
	BOOL Write(DWORD pid, ULONG64 address, T data);

	// ���ڴ�DWORD
	VOID ReadMemoryDWORD(DWORD pid, ULONG64 addre, DWORD * ret);

	// ���ڴ�DWORD64
	VOID ReadMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 * ret);

	// ���ڴ��ֽ�
	VOID ReadMemoryBytes(DWORD pid, ULONG64 addre, BYTE **ret, DWORD sizes);

	// ���ڴ渡����
	VOID ReadMemoryFloat(DWORD pid, ULONG64 addre, float* ret);

	// ���ڴ�˫���ȸ�����
	VOID ReadMemoryDouble(DWORD pid, ULONG64 addre, double* ret);

	// д�ڴ��ֽ�
	VOID WriteMemoryBytes(DWORD pid, ULONG64 addre, BYTE * data, DWORD sizes);

	// д�ڴ�DWORD
	VOID WriteMemoryDWORD(DWORD pid, ULONG64 addre, DWORD ret);

	// д�ڴ�DWORD64
	VOID WriteMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 ret);

	// д�ڴ渡����
	VOID WriteMemoryFloat(DWORD pid, ULONG64 addre, float ret);

	// д�ڴ�˫���ȸ�����
	VOID WriteMemoryDouble(DWORD pid, ULONG64 addre, double ret);

	// ������ȡ����ģ�����ַ
	DWORD64 GetModuleAddress(DWORD pid, std::string dllname);

	// ���ݽ������ƻ�ȡ����PID
	DWORD GetProcessID(std::string procname);

	// ��ȡϵͳ�����ڴ��ַ
	DWORD64 GetSystemRoutineAddress(std::string funcname);

	// �ڶԶ˷����ڴ�ռ�
	DWORD64 CreateRemoteMemory(DWORD length);

	// ���ٶԶ��ڴ�
	DWORD DeleteRemoteMemory(DWORD64 address, DWORD length);

	// ------------------------------------------------------------------
	// ˽�������뺯��
	// ------------------------------------------------------------------
public:
	// ��ȡ������
	BOOL GetSvcHandle(PCHAR pServiceName);

	// ��ȡ�����źŶ�Ӧ�ַ���
	DWORD CTL_CODE_GEN(DWORD lngFunction);

	// ��ȡ����·��
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