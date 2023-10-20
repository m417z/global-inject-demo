#pragma once

#include <windows.h>
#include <filesystem>

BOOL GetFullAccessSecurityDescriptor(_Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor, _Out_opt_ PULONG SecurityDescriptorSize);
BOOL CheckWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion, WORD wServicePackMajor, WORD wServicePackMinor, int op);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL SetDebugPrivilege(BOOL bEnablePrivilege);
std::filesystem::path GetEnginePath(USHORT* pMachine = nullptr);
std::filesystem::path GetDllFileName();
USHORT GetProcessArch(HANDLE hProcess);
