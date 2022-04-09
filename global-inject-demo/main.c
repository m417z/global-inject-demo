#include <windows.h>
#include <stdio.h>

#define WAITING_EVENT_NAME L"Global\\GlobalHookEvent.{B89D7EDC-04A4-49AF-9BD2-8598D6CB1D34}"

#ifndef _WIN64
#define DLL_FILE_NAME L"global-inject-lib.dll"
#else // _WIN64
#define DLL_FILE_NAME L"global-inject-lib_x64.dll"
#endif // _WIN64

// SetPrivilege enables/disables process token privilege.
// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	BOOL bRet = FALSE;

	if(LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		//
		//  Enable the privilege or disable all privileges.
		//
		if(AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))
		{
			//
			//  Check to see if you have proper access.
			//  You may get "ERROR_NOT_ALL_ASSIGNED".
			//
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}
	return bRet;
}

int main(int argc, char **argv)
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if(OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		BOOL bSucceeded = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		CloseHandle(hToken);
		printf("SetPrivilege(SE_DEBUG_NAME): %d\n", bSucceeded);
	}
	else
		printf("OpenProcessToken(TOKEN_ADJUST_PRIVILEGES) failed with %u\n", GetLastError());

	if(argc == 2 && strcmp(argv[1], "-u") == 0)
	{
		printf("Signaling to unload injected DLL...\n");

		HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, WAITING_EVENT_NAME);
		if(hEvent)
		{
			printf("Event opened: %p\n", hEvent);

			BOOL bSucceeded = SetEvent(hEvent);
			printf("Event set: %d\n", bSucceeded);

			CloseHandle(hEvent);
		}
		else
			printf("Event wasn't opened: error %u\n", GetLastError());
	}
	else
	{
		printf("Injecting...\n");

		WCHAR szDllPath[MAX_PATH];
		int i = GetModuleFileName(NULL, szDllPath, MAX_PATH);
		while(i-- && szDllPath[i] != L'\\');
		lstrcpy(&szDllPath[i + 1], DLL_FILE_NAME);

		HMODULE hMod = LoadLibrary(szDllPath);
		BOOL(__stdcall *pSetGlobalHook)(void);
		*(FARPROC *)&pSetGlobalHook = GetProcAddress(hMod, "SetGlobalHook");

		BOOL bSucceeded = pSetGlobalHook();

		printf("Injection completed: %d\n", bSucceeded);
	}

	return 0;
}
