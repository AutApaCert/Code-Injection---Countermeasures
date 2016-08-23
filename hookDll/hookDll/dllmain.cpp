
#include "mhook-lib\mhook.h"

typedef DWORD(WINAPI * functypeNtCreateThreadEx)(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   Unknown1,
	DWORD                   Unknown2,
	LPVOID                  Unknown3
	);

functypeNtCreateThreadEx    pNtCreateThreadEx = (functypeNtCreateThreadEx)
GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
BOOL WINAPI MyNtCreateThreadEx
(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   Unknown1,
	DWORD                   Unknown2,
	LPVOID                  Unknown3
)
{
	if ((GetCurrentProcessId()) != (GetProcessId(ProcessHandle)))
	{
		HMODULE hModule = GetModuleHandle(L"kernel32.dll");

		LPTHREAD_START_ROUTINE LoadLibAAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
		LPTHREAD_START_ROUTINE LoadLibWAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
		LPTHREAD_START_ROUTINE LoadLibExAAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryExA");
		LPTHREAD_START_ROUTINE LoadLibExWAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryExW");
		LPTHREAD_START_ROUTINE lpsr = (LPTHREAD_START_ROUTINE)lpStartAddress;

		if (((*lpsr) != (*LoadLibAAddr)) && ((*lpsr) != (*LoadLibWAddr)) && ((*lpsr) != (*LoadLibExAAddr)) && ((*lpsr) != (*LoadLibExWAddr)))
			return 0;
	}

	return pNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
		lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		try
		{
			Mhook_SetHook((PVOID*)&pNtCreateThreadEx, MyNtCreateThreadEx);
		}
		catch (int e)
		{ }

		break;
	case DLL_THREAD_ATTACH:
		
		try
		{
			Mhook_SetHook((PVOID*)&pNtCreateThreadEx, MyNtCreateThreadEx);
		}
		catch (int e)
		{ }

		break;
	case DLL_THREAD_DETACH:
		
		try
		{
			Mhook_Unhook((PVOID*)&pNtCreateThreadEx);

		}
		catch (int e)
		{ }

		break;
	case DLL_PROCESS_DETACH:
		
		try
		{
			Mhook_Unhook((PVOID*)&pNtCreateThreadEx);
		}
		catch (int e)
		{ }

		break;
	}
	return TRUE;
}