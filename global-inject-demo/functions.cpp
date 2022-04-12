#include "stdafx.h"
#include "functions.h"

// SetPrivilege enables/disables process token privilege.
// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(nullptr, lpszPrivilege, &luid)) {
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		// Enable the privilege or disable all privileges.
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
			// Check to see if you have proper access.
			// You may get "ERROR_NOT_ALL_ASSIGNED".
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}

	return bRet;
}

BOOL SetDebugPrivilege(BOOL bEnablePrivilege)
{
	wil::unique_handle token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		return FALSE;
	}

	return SetPrivilege(token.get(), SE_DEBUG_NAME, bEnablePrivilege);
}
