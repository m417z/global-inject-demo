#include <windows.h>
#include <tlhelp32.h>
#include "all_processes_injector.h"
#include "dll_inject.h"
#include "logger.h"

BOOL InjectDllToAllProcesses(HINSTANCE hDllInst)
{
	LOG(L"Running InjectDllToAllProcesses");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		LOG(L"CreateToolhelp32Snapshot failed with error %u", GetLastError());
		return FALSE;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hSnapshot, &pe))
	{
		LOG(L"Process32First failed with error %u", GetLastError());
		return FALSE;
	}

	do
	{
		LOG(L"Iterating process %u (%s)", pe.th32ProcessID, pe.szExeFile);

		if(pe.th32ProcessID == GetCurrentProcessId())
		{
			LOG(L"Skipping current process");
			continue;
		}

		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
			PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pe.th32ProcessID);
		if(hProcess)
		{
			LOG(L"Opened process %u, injecting...", pe.th32ProcessID);

			DWORD dwError = DllInject(hProcess, hDllInst, 1000);

			LOG(L"DllInject returned %u", dwError);

			CloseHandle(hProcess);
		}
		else
			LOG(L"OpenProcess failed with error %u", GetLastError());

		pe.dwSize = sizeof(PROCESSENTRY32);
	}
	while(Process32Next(hSnapshot, &pe));

	DWORD dwError = GetLastError();

	if(dwError == ERROR_NO_MORE_FILES)
		LOG(L"Iteration finished successfully");
	else
		LOG(L"Iteration finished with error %u", dwError);

	CloseHandle(hSnapshot);
	return TRUE;
}
