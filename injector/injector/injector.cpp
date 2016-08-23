// injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <string>
#include "Shlwapi.h"
#include "SetPriv.h"

#pragma comment(lib, "Shlwapi.lib")
using namespace std;

typedef NTSTATUS(NTAPI* NTSUSPEND)(HANDLE hProcess);
typedef NTSTATUS(NTAPI* NTRESUME)(HANDLE hProcess);
char filePath[1024];
#include <windows.h>
#pragma comment(lib,"user32.lib")

#define _WIN32_WINNT 0x0400

typedef LONG NTSTATUS, *PNTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

int injectDllIntoPID(int process)
{
	DWORD pid = (DWORD)process;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		wcout << "Cannot open process: " << process << " error: " << GetLastError() << endl;
		exit(1);
	}
	wcout << "Open process " << process << ": OK" << endl;

	//Retrieves kernel32.dll module handle for getting loadlibrary base address
	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	//Gets address for LoadLibraryA in kernel32.dll
	LPVOID lpBaseAddress = (LPVOID)GetProcAddress(hModule, "LoadLibraryA");

	if (lpBaseAddress == NULL)
	{
		wcout<<"Unable to locate LoadLibraryA"<<endl;
		return -1;
	}

	//Allocates space inside for inject.dll to our target process
	LPVOID lpSpace = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(filePath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpSpace == NULL)
	{
		CloseHandle(lpSpace);
		wcout<<"Could not allocate memory in process "<< (int)process<< ", error: " << GetLastError() << endl;
		exit(1);
	}
	wcout << "Memory allocation: OK" << endl;

	//Write inject.dll to memory of process
	if (!WriteProcessMemory(hProcess, lpSpace, filePath, sizeof(filePath), NULL))
	{
		wcout << "Cannot write the shellcode in the process memory, error: " << process << ", error: " << GetLastError() << endl;
		exit(1);
	}

	wcout << "DLL copied in memory: OK" << endl;

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, NULL, NULL);

	if (hThread == NULL)
	{
		wcout << "Thread creation failed, error: " << endl;
		return -1;
	}
	else
	{
		wcout << "Injection: OK" << endl;

		CloseHandle(hProcess);
		return 0;
	}
}

int injectShellcodeIntoPID(int process)
{
	NTSUSPEND NtSuspendProcess = (NTSUSPEND)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
	NTRESUME NtResumeProcess = (NTRESUME)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess");
	//Shellcode injection
	HANDLE hProcess = NULL;
	LPVOID hAllocatedMem = NULL;
	HANDLE hThread = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		wcout << "Cannot open process: " << process << " error: " << GetLastError() << endl;
		exit(1);
	}
	wcout << "Open process " << process << ": OK" << endl;

	NtSuspendProcess(hProcess);

	hAllocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(filePath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (hAllocatedMem == NULL)
	{
		CloseHandle(hAllocatedMem);
		wcout << "Cannot allocate memory in " << process << ", error: " << GetLastError() << endl;
		exit(1);
	}
	wcout << "Memory allocation: OK" << endl;

	if (!WriteProcessMemory(hProcess, hAllocatedMem, filePath, sizeof(filePath), NULL))
	{
		wcout << "Cannot write the shellcode in the process memory, error: " << process << ", error: " << GetLastError() << endl;
		exit(1);
	}
	wcout << "Shellcode copied in memory: OK" << endl;


	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hAllocatedMem, NULL, NULL, 0);
	if (hThread == NULL)
	{
		wcout << "Thread creation failed, error: " << endl;
		exit(1);
	}

	int nInjectOK = 0;
	NtResumeProcess(hProcess);
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, (PDWORD)&nInjectOK);
	wcout << "Injection: OK" << endl;
	if (!nInjectOK)
		VirtualFreeEx(hProcess, hAllocatedMem, 0, MEM_RELEASE);

	if (hThread != 0)
	{
		CloseHandle(hThread);
		return 0;
	}
	else
		return -1;
		
}

void usage(_TCHAR* binary)
{
	wcerr << "Usage of the injector. " << endl;
	wcerr << endl;
	wcerr << binary << " /d full_path_to_dll_file PID" << endl;
	wcerr << binary << " /s full_path_to_shellcode_file PID" << endl;
	wcerr << "    /d full_path_to_dll_file PID: dll injection via LoadLibrary()." << endl;
	wcerr << "    /s full_path_to_shellcode_file PID: shellcode injection." << endl;
	exit(1);
}

int _tmain(int argc, _TCHAR* argv[])
{
	int option = 0;
	DWORD PID;
	SetPriv SeDebug;

	if (argc != 4)
		usage(argv[0]);

	if (!wcscmp(argv[1], _T("/d")))
		option = 1;
	else if (!wcscmp(argv[1], _T("/s")))
		option = 2;
	else
		usage(argv[0]);

	if (!PathFileExists(argv[2]))
		usage(argv[0]);
	
	PID = _ttoi(argv[3]);
	
	//Set SeDebugPriviliege
	cout << "Set SeDebugPrivilege: ";
	if (!SeDebug.CheckPriv())
	{
		wcout << "KO: cannot obtain the adjust|query privilege." << endl;
		exit(1);
	}
	if (!SeDebug.Set(SE_DEBUG_NAME, TRUE))
	{
		wcout << "KO: cannot obtain the SeDebug privilege." << endl;
		exit(1);
	}
	cout << "OK" << endl;

	if (option == 1)
	{

		size_t i = 1024;

		wcstombs_s(&i, filePath, 1024, argv[2], 1024);

		injectDllIntoPID(PID);

		return 0;

	}
	else if (option == 2)
	{
		ifstream file;
		string line;
		char *sc;

		file.open(argv[2], ios::binary);
		if (!file.is_open())
		{
			wcout << "KO: " << "Cannot open the file " << argv[2] << endl;
			exit(1);
		}
		getline(file, line);
		file.close();
		sc = new char[line.size() + 1];
		sc = (char*)line.c_str();

		size_t i = 1024;

		memcpy(filePath, sc, line.size() + 1);

		injectShellcodeIntoPID(PID);

		return 0;
	}
}