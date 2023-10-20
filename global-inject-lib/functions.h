#pragma once

#include <windows.h>

#include "common_functions.h"

HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, USHORT targetProcessArch);
ULONG64 EncodeWow64ApcRoutine(ULONG64 ApcRoutine);
BOOL MyQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData, USHORT targetProcessArch);
