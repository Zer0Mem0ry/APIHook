#include <Windows.h>

struct hook_t
{
	bool isHooked;
	void* FunctionAddress;
	void* Hook;
	char  Jmp[6];
	char  APIBytes[6];
	void* APIFunction;
};

namespace hook
{
	bool InitializeHook(hook_t* Hook, char* ModuleName, char* FunctionName, void* HookFunction)
	{
		HMODULE hModule;
		ULONG OrigFunc, FuncAddr;
		char opcodes[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9, 0x00, 0x00, 0x00, 0x00 };

		if (Hook->isHooked) {
			return false;
		}
		hModule = GetModuleHandle(ModuleName);
		if (hModule == NULL) {
			Hook->isHooked = false;
			return false;
		}
		Hook->FunctionAddress = GetProcAddress(hModule, FunctionName);
		if (Hook->FunctionAddress == NULL) {
			Hook->isHooked = false;
			return false;
		}
		Hook->Jmp[0] = 0xe9;
		*(PULONG)&Hook->Jmp[1] = (ULONG)HookFunction - (ULONG)Hook->FunctionAddress - 5;
		memcpy(Hook->APIBytes, Hook->FunctionAddress, 5);
		Hook->APIFunction = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (Hook->APIFunction == NULL) {
			return false;
		}
		memcpy(Hook->APIFunction, Hook->APIBytes, 5);
		OrigFunc = (ULONG)Hook->APIFunction + 5;
		FuncAddr = (ULONG)Hook->FunctionAddress + 5;
		*(LPBYTE)((LPBYTE)Hook->APIFunction + 5) = 0xe9;
		*(PULONG)((LPBYTE)Hook->APIFunction + 6) = (ULONG)FuncAddr - (ULONG)OrigFunc - 5;
		Hook->isHooked = true;
		return true;
	}

	bool InitializeByAddress(hook_t* Hook, void* Address, void* HookFunction)
	{
		ULONG OrigFunction, FunctionAddress;
		char opcodes[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9, 0x00, 0x00, 0x00, 0x00 };
		if (Hook->isHooked) {
			return false;
		}
		Hook->FunctionAddress = Address;
		Hook->Jmp[0] = 0xe9;

		*(PULONG)&Hook->Jmp[1] = (ULONG)HookFunction - (ULONG)Hook->FunctionAddress - 5;
		memcpy(Hook->APIBytes, Hook->FunctionAddress, 5);

		Hook->APIFunction = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		memcpy(Hook->APIFunction, Hook->APIBytes, 5);

		OrigFunction = (ULONG)Hook->APIFunction + 5;
		FunctionAddress = (ULONG)Hook->FunctionAddress + 5;

		*(LPBYTE)((LPBYTE)Hook->APIFunction + 5) = 0xe9;
		*(PULONG)((LPBYTE)Hook->APIFunction + 6) = (ULONG)FunctionAddress - (ULONG)OrigFunction - 5;
		Hook->isHooked = true;
		return true;
	}

	bool InsertHook(hook_t* Hook)
	{
		DWORD op;
		if (!Hook->isHooked) {
			return false;
		}
		VirtualProtect(Hook->FunctionAddress, 5, PAGE_EXECUTE_READWRITE, &op);
		memcpy(Hook->FunctionAddress, Hook->Jmp, 5);
		VirtualProtect(Hook->FunctionAddress, 5, op, &op);
		return true;
	}

	bool Unhook(hook_t* Hook)
	{
		DWORD op;
		if (!Hook->isHooked) {
			return false;
		}
		VirtualProtect(Hook->FunctionAddress, 5, PAGE_EXECUTE_READWRITE, &op);
		memcpy(Hook->FunctionAddress, Hook->APIBytes, 5);
		VirtualProtect(Hook->FunctionAddress, 5, op, &op);

		Hook->isHooked = false;
		return true;
	}

	bool FreeHook(hook_t* Hook)
	{
		if (Hook->isHooked) {
			return false;
		}
		VirtualFree(Hook->APIFunction, 0, MEM_RELEASE);
		memset(Hook, 0, sizeof(hook_t*));
		return true;
	}
};