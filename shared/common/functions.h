#pragma once

#include <windows.h>
#include <filesystem>

BOOL GetFullAccessSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_opt_ PULONG SecurityDescriptorSize);

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL SetDebugPrivilege(BOOL bEnablePrivilege);
std::filesystem::path GetEnginePath(USHORT* pMachine = nullptr);
std::filesystem::path GetDllFileName();

HANDLE MyCreateRemoteThread(HANDLE hProcess,
  LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, USHORT targetProcessArch);
ULONG64 EncodeWow64ApcRoutine(ULONG64 ApcRoutine);
BOOL MyQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData, USHORT targetProcessArch);
USHORT GetProcessArch(HANDLE hProcess);
