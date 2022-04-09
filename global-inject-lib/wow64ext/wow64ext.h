/**
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2014 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include <windows.h>

struct _CONTEXT64;

#ifdef __cplusplus
extern "C" {
#endif

VOID Wow64ExtInitialize();
DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
DWORD64 __cdecl GetModuleHandle64(wchar_t* lpModuleName);
DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, char* funcName);
SIZE_T __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength);
DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
BOOL __cdecl GetThreadContext64(HANDLE hThread, struct _CONTEXT64* lpContext);
BOOL __cdecl SetThreadContext64(HANDLE hThread, struct _CONTEXT64* lpContext);
VOID __cdecl SetLastErrorFromX64Call(DWORD64 status);
DWORD64 __cdecl LoadLibraryW64(LPCWSTR lpLibFileName);
DWORD64 __cdecl MyCreateRemoteThread64(DWORD64 hProcess, DWORD64 remote_addr, DWORD64 thread_arg);
BOOL __cdecl CloseHandle64(DWORD64 Handle);

#ifdef __cplusplus
}
#endif
