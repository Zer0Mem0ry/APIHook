#include <Windows.h>
#include <TlHelp32.h>

typedef BOOL(WINAPI *fWriteProcessMemory)(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	);
typedef BOOL(WINAPI *fReadProcessMemory)(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	);


fWriteProcessMemory hookWpm;
fReadProcessMemory hookRpm;

unsigned long attach(char* pName)
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	do
		if (!strcmp(entry.szExeFile, pName)) {
			CloseHandle(handle);
			return entry.th32ProcessID;
		}
	while (Process32Next(handle, &entry));
	return false;
}

//this will replace the DeleteFileA function in our target process
BOOL WINAPI HookWriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	)
{
	if (OpenProcess(PROCESS_ALL_ACCESS, false, attach("Helix V3.exe")) == hProcess)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		MessageBoxA(0, "Can't write memory of this process!", "Error!", 0);
		return false;
	}
	return hookWpm(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten); //if the parameter does not contain this string, call the original API function
}

BOOL WINAPI HookReadProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	)
{
	if (OpenProcess(PROCESS_ALL_ACCESS, false, attach("Helix V3.exe")) == hProcess)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		MessageBoxA(0, "Can't read memory of this process!", "Error!", 0);
		return false;
	}
	return hookRpm(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead); //if the parameter does not contain this string, call the original API function
}