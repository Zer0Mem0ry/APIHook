#include <Windows.h>
#include "apihook.h"
#include "apifunctions.h"

using namespace hook;
hook_t Hook;

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		InitializeHook(&Hook, "kernel32.dll", "ReadProcessMemory", HookWriteProcessMemory);
		InitializeHook(&Hook, "kernel32.dll", "WriteProcessMemory", HookWriteProcessMemory);

		hookRpm = (fReadProcessMemory)Hook.APIFunction;
		hookWpm = (fWriteProcessMemory)Hook.APIFunction;
		InsertHook(&Hook);
	}
	else if (dwReason == DLL_PROCESS_DETACH) 
	{
		Unhook(&Hook);
		FreeHook(&Hook);
	}
	return TRUE;
}