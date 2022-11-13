cDrvCtrl DriveControl;

// 安装驱动
extern "C"__declspec(dllexport) void InstallDriver()
{
	DriveControl.InstallAndRun();
}

// 卸载关闭驱动
extern "C" __declspec(dllexport) void RemoveDriver()
{
	DriveControl.RemoveAndStop();
}

// 通用驱动导出
extern "C" __declspec(dllexport) BYTE ReadProcessMemoryByte(DWORD pid, ULONG64 address)
{
	return DriveControl.ReadProcessMemoryByte(pid, address);
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryByte(DWORD Pid, ULONG64 Address, BYTE bytef)
{
	return DriveControl.WriteProcessMemoryByte(Pid, Address, bytef);
}

extern "C" __declspec(dllexport) DWORD ReadProcessMemoryInt32(DWORD Pid, ULONG64 Address)
{
	return DriveControl.ReadProcessMemoryInt32(Pid, Address);
}

extern "C" __declspec(dllexport) DWORD ReadProcessMemoryInt64(DWORD Pid, ULONG64 Address)
{
	return DriveControl.ReadProcessMemoryInt64(Pid, Address);
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryInt32(DWORD Pid, ULONG64 Address, DWORD write)
{
	return DriveControl.WriteProcessMemoryInt32(Pid, Address, write);
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryInt64(DWORD Pid, ULONG64 Address, DWORD write)
{
	return DriveControl.WriteProcessMemoryInt64(Pid, Address, write);
}

extern "C" __declspec(dllexport) FLOAT ReadProcessMemoryFloat(DWORD Pid, ULONG64 Address)
{
	return DriveControl.ReadProcessMemoryFloat(Pid, Address);
}

extern "C" __declspec(dllexport) DOUBLE ReadProcessMemoryDouble(DWORD Pid, ULONG64 Address)
{
	return DriveControl.ReadProcessMemoryDouble(Pid, Address);
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryFloat(DWORD Pid, ULONG64 Address, FLOAT write)
{
	return DriveControl.WriteProcessMemoryFloat(Pid, Address, write);
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemoryDouble(DWORD Pid, ULONG64 Address, DOUBLE write)
{
	return DriveControl.WriteProcessMemoryDouble(Pid, Address, write);
}

extern "C" __declspec(dllexport) INT32 ReadProcessDeviationInt32(ProcessDeviationIntMemory read_offset_struct)
{
	return DriveControl.ReadProcessDeviationInt32(&read_offset_struct);
}

extern "C" __declspec(dllexport) INT64 ReadProcessDeviationInt64(ProcessDeviationIntMemory read_offset_struct)
{
	return DriveControl.ReadProcessDeviationInt64(&read_offset_struct);
}

extern "C" __declspec(dllexport) BOOL WriteProcessDeviationInt32(ProcessDeviationIntMemory write_offset_struct)
{
	return DriveControl.WriteProcessDeviationInt32(&write_offset_struct);
}

extern "C" __declspec(dllexport) BOOL WriteProcessDeviationInt64(ProcessDeviationIntMemory write_offset_struct)
{
	return DriveControl.WriteProcessDeviationInt64(&write_offset_struct);
}

extern "C" __declspec(dllexport) DWORD ReadDeviationMemory32(ProcessDeviationMemory read_offset_struct)
{
	return DriveControl.ReadDeviationMemory32(&read_offset_struct);
}

extern "C" __declspec(dllexport) DWORD64 ReadDeviationMemory64(ProcessDeviationMemory read_offset_struct)
{
	return DriveControl.ReadDeviationMemory64(&read_offset_struct);
}

extern "C" __declspec(dllexport) BYTE ReadDeviationByte(ProcessDeviationMemory read_offset_struct)
{
	return DriveControl.ReadDeviationByte(&read_offset_struct);
}

extern "C" __declspec(dllexport) FLOAT ReadDeviationFloat(ProcessDeviationMemory read_offset_struct)
{
	return DriveControl.ReadDeviationFloat(&read_offset_struct);
}

extern "C" __declspec(dllexport) BOOL WriteDeviationByte(ProcessDeviationMemory write_offset_struct, BYTE write_byte)
{
	return DriveControl.WriteDeviationByte(&write_offset_struct, write_byte);
}

extern "C" __declspec(dllexport) BOOL WriteDeviationFloat(ProcessDeviationMemory write_offset_struct, FLOAT write_float)
{
	return DriveControl.WriteDeviationFloat(&write_offset_struct, write_float);
}

// 全局读写
extern "C" __declspec(dllexport) BOOL SetPid(DWORD Pid)
{
	return DriveControl.SetPid(Pid);
}

extern "C" __declspec(dllexport) void ReadMemoryDWORD(DWORD pid, ULONG64 addre, DWORD ret)
{
	return DriveControl.ReadMemoryDWORD(pid, addre, &ret);
}

extern "C" __declspec(dllexport) void ReadMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 ret)
{
	return DriveControl.ReadMemoryDWORD64(pid, addre, &ret);
}

extern "C" __declspec(dllexport) void ReadMemoryBytes(DWORD pid, ULONG64 addre, BYTE *ret, DWORD sizes)
{
	return DriveControl.ReadMemoryBytes(pid, addre, &ret, sizes);
}

extern "C" __declspec(dllexport) void ReadMemoryFloat(DWORD pid, ULONG64 addre, float ret)
{
	return DriveControl.ReadMemoryFloat(pid, addre, &ret);
}

extern "C" __declspec(dllexport) void ReadMemoryDouble(DWORD pid, ULONG64 addre, double ret)
{
	return DriveControl.ReadMemoryDouble(pid, addre, &ret);
}

extern "C" __declspec(dllexport) void WriteMemoryBytes(DWORD pid, ULONG64 addre, BYTE data, DWORD sizes)
{
	return DriveControl.WriteMemoryBytes(pid, addre, &data, sizes);
}

extern "C" __declspec(dllexport) void WriteMemoryDWORD(DWORD pid, ULONG64 addre, DWORD ret)
{
	return DriveControl.WriteMemoryDWORD(pid, addre, ret);
}

extern "C" __declspec(dllexport) void WriteMemoryDWORD64(DWORD pid, ULONG64 addre, DWORD64 ret)
{
	return DriveControl.WriteMemoryDWORD64(pid, addre, ret);
}

extern "C" __declspec(dllexport) void WriteMemoryFloat(DWORD pid, ULONG64 addre, float ret)
{
	return DriveControl.WriteMemoryFloat(pid, addre, ret);
}

extern "C" __declspec(dllexport) void WriteMemoryDouble(DWORD pid, ULONG64 addre, double ret)
{
	return DriveControl.WriteMemoryDouble(pid, addre, ret);
}

extern "C" __declspec(dllexport) DWORD64 GetModuleAddress(DWORD pid, std::string dllname)
{
	return DriveControl.GetModuleAddress(pid, dllname);
}

extern "C" __declspec(dllexport) DWORD GetProcessID(std::string procname)
{
	return DriveControl.GetProcessID(procname);
}

extern "C" __declspec(dllexport) DWORD64 GetSystemRoutineAddress(std::string funcname)
{
	return DriveControl.GetSystemRoutineAddress(funcname);
}

extern "C" __declspec(dllexport) DWORD64 CreateRemoteMemory(DWORD length)
{
	return DriveControl.CreateRemoteMemory(length);
}

extern "C" __declspec(dllexport) DWORD DeleteRemoteMemory(DWORD64 address, DWORD length)
{
	return DriveControl.DeleteRemoteMemory(address, length);
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
	return TRUE;
}
