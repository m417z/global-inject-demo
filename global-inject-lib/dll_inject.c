#include <windows.h>
#include <ntsecapi.h>
#include "dll_inject.h"
#include "logger.h"
#include "wow64ext/wow64ext.h"

#define INJECT_DLL_FILE_NAME_32    L"global-inject-lib"
#define INJECT_DLL_FILE_NAME_64    L"global-inject-lib_x64.dll"

#define PRE_X32SHELLCODE_VIRTUAL_FREE \
	"\xFF\x74\x24\x04"     /* push dword ptr ss:[esp+4]    */ \
	"\xE8\x23\x00\x00\x00" /* call $+23                    */ \
	"\x8B\x4C\x24\x04"     /* mov ecx,dword ptr ss:[esp+4] */ \
	"\x36\x8B\x09"         /* mov ecx,dword ptr ss:[ecx]   */ \
	"\x85\xC9"             /* test ecx,ecx                 */ \
	"\x75\x03"             /* jne $+3                      */ \
	"\xC2\x04\x00"         /* ret 4                        */ \
	"\x58"                 /* pop eax                      */ \
	"\x5A"                 /* pop edx                      */ \
	"\x68\x00\x80\x00\x00" /* push 8000                    */ \
	"\x6A\x00"             /* push 0                       */ \
	"\xE8\x00\x00\x00\x00" /* call $                       */ \
	"\x83\x2C\x24\x25"     /* sub dword ptr ss:[esp],25    */ \
	"\x50"                 /* push eax                     */ \
	"\xFF\xE1"             /* jmp ecx                      */

static const SIZE_T preX32ShellcodeSize = sizeof(PRE_X32SHELLCODE_VIRTUAL_FREE) - 1;

// The 32-bit InjectShellcode function from the project in the inject-shellcode subfolder.
static const BYTE x32Shellcode[] =
	PRE_X32SHELLCODE_VIRTUAL_FREE
	"\x55\x8B\xEC\x83\xEC\x30\x8B\x45\x08\x33\xD2\x53\x56\xC7\x45\xD0"
	"\x49\x6E\x6A\x65\x33\xDB\xC7\x80\x10\x02\x00\x00\x22\x4E\x00\x00"
	"\x33\xC9\x64\xA1\x30\x00\x00\x00\xC7\x45\xD4\x63\x74\x49\x6E\x66"
	"\xC7\x45\xD8\x69\x74\xC6\x45\xDA\x00\x8B\x70\x0C\x8B\x46\x14\x83"
	"\xC6\x14\x57\x33\xFF\x89\x55\xE4\x89\x7D\xF4\x89\x5D\xE8\x89\x4D"
	"\xFC\x89\x75\xDC\x89\x45\xF0\x3B\xC6\x0F\x84\x3A\x01\x00\x00\x90"
	"\x8B\x70\x28\x33\xC9\x0F\xB7\x50\x24\x0F\x1F\x80\x00\x00\x00\x00"
	"\x0F\xB6\x3E\xC1\xC9\x0D\x80\x3E\x61\x72\x03\x83\xC1\xE0\x81\xC2"
	"\xFF\xFF\x00\x00\x03\xCF\x46\x66\x85\xD2\x75\xE4\x81\xF9\x5B\xBC"
	"\x4A\x6A\x0F\x85\xD7\x00\x00\x00\x8B\x75\xF0\xBB\x04\x00\x00\x00"
	"\x8B\x76\x10\x8B\x46\x3C\x8B\x54\x30\x78\x8B\x44\x32\x20\x03\xD6"
	"\x03\xC6\x89\x55\xE0\x89\x45\xEC\x8B\x4A\x24\x8B\x7A\x18\x03\xCE"
	"\x89\x4D\xF8\x85\xFF\x0F\x84\xA1\x00\x00\x00\x8B\x10\x03\xD6\x33"
	"\xC0\x8A\x0A\xC1\xC8\x0D\x8D\x52\x01\x0F\xBE\xC9\x03\xC1\x8A\x0A"
	"\x84\xC9\x75\xEF\x3D\xA4\x4E\x0E\xEC\x74\x15\x3D\xAA\xFC\x0D\x7C"
	"\x74\x0E\x3D\xA0\xD5\xC9\x4D\x74\x07\x3D\xAC\x33\x06\x03\x75\x55"
	"\x8B\x4D\xF8\x0F\xB7\x11\x8B\x4D\xE0\x8B\x49\x1C\x8D\x0C\x91\x03"
	"\xCE\x3D\xA4\x4E\x0E\xEC\x75\x09\x8B\x01\x03\xC6\x89\x45\xE4\xEB"
	"\x2E\x3D\xAA\xFC\x0D\x7C\x75\x09\x8B\x01\x03\xC6\x89\x45\xF4\xEB"
	"\x1E\x3D\xA0\xD5\xC9\x4D\x75\x09\x8B\x01\x03\xC6\x89\x45\xE8\xEB"
	"\x0E\x3D\xAC\x33\x06\x03\x75\x07\x8B\x01\x03\xC6\x89\x45\xFC\x81"
	"\xC3\xFF\xFF\x00\x00\x8B\x45\xEC\x4F\x83\x45\xF8\x02\x83\xC0\x04"
	"\x89\x45\xEC\x66\x85\xDB\x0F\x85\x57\xFF\xFF\xFF\x8B\x5D\xE8\x8B"
	"\x55\xE4\x8B\x7D\xF4\x8B\x4D\xFC\x85\xD2\x74\x0C\x85\xFF\x74\x08"
	"\x85\xDB\x74\x04\x85\xC9\x75\x11\x8B\x45\xF0\x8B\x00\x89\x45\xF0"
	"\x3B\x45\xDC\x0F\x85\xC7\xFE\xFF\xFF\x8B\x45\x08\x89\x08\x85\xD2"
	"\x0F\x84\x9E\x00\x00\x00\x85\xFF\x0F\x84\x96\x00\x00\x00\x85\xDB"
	"\x0F\x84\x8E\x00\x00\x00\x85\xC9\x0F\x84\x86\x00\x00\x00\xC7\x80"
	"\x10\x02\x00\x00\x26\x4E\x00\x00\x83\xC0\x08\x50\xFF\xD2\x8B\xF0"
	"\x8B\x45\x08\x85\xF6\x74\x55\xC7\x80\x10\x02\x00\x00\x28\x4E\x00"
	"\x00\x8D\x45\xD0\x50\x56\xFF\xD7\x85\xC0\x74\x22\x8B\x7D\x08\xC7"
	"\x87\x10\x02\x00\x00\x2A\x4E\x00\x00\xFF\xD0\x89\x87\x10\x02\x00"
	"\x00\x85\xC0\x75\x16\x5F\x5E\x5B\x8B\xE5\x5D\xC2\x04\x00\x8B\x45"
	"\x08\xC7\x80\x10\x02\x00\x00\x29\x4E\x00\x00\x56\xFF\xD3\x5F\x5E"
	"\xB8\x01\x00\x00\x00\x5B\x8B\xE5\x5D\xC2\x04\x00\x5F\x5E\xC7\x80"
	"\x10\x02\x00\x00\x27\x4E\x00\x00\xB8\x01\x00\x00\x00\x5B\x8B\xE5"
	"\x5D\xC2\x04\x00\x5F\x5E\xC7\x80\x10\x02\x00\x00\x23\x4E\x00\x00"
	"\xB8\x01\x00\x00\x00\x5B\x8B\xE5\x5D\xC2\x04\x00";

static const SIZE_T x32ShellcodeSize = sizeof(x32Shellcode) - 1;

#define PRE_X64SHELLCODE_VIRTUAL_FREE \
	"\x53"                         /* push rbx                       */ \
	"\x48\x83\xEC\x20"             /* sub rsp,20                     */ \
	"\x48\x8B\xD9"                 /* mov rbx,rcx                    */ \
	"\xE8\x20\x00\x00\x00"         /* call $+20                      */ \
	"\x4C\x8B\x0B"                 /* mov r9,qword ptr ds:[rbx]      */ \
	"\x48\x83\xC4\x20"             /* add rsp,20                     */ \
	"\x5B"                         /* pop rbx                        */ \
	"\x4D\x85\xC9"                 /* test r9,r9                     */ \
	"\x75\x01"                     /* jne $+1                        */ \
	"\xC3"                         /* ret                            */ \
	"\x48\x8D\x0D\xDE\xFF\xFF\xFF" /* lea rcx,qword ptr ds:[<start>] */ \
	"\x33\xD2"                     /* xor edx,edx                    */ \
	"\x41\xB8\x00\x80\x00\x00"     /* mov r8d,8000                   */ \
	"\x41\xFF\xE1"                 /* jmp r9                         */

static const SIZE_T preX64ShellcodeSize = sizeof(PRE_X64SHELLCODE_VIRTUAL_FREE) - 1;

// The 64-bit InjectShellcode function from the project in the inject-shellcode subfolder.
static const BYTE x64Shellcode[] =
	PRE_X64SHELLCODE_VIRTUAL_FREE
	"\x48\x8B\xC4\x48\x89\x48\x08\x53\x55\x56\x57\x41\x56\x41\x57\x48"
	"\x83\xEC\x38\xC7\x40\xB8\x49\x6E\x6A\x65\x45\x33\xF6\xC7\x40\xBC"
	"\x63\x74\x49\x6E\x45\x33\xFF\x66\xC7\x40\xC0\x69\x74\x33\xED\xC6"
	"\x40\xC2\x00\x33\xF6\xC7\x81\x10\x02\x00\x00\x22\x4E\x00\x00\x48"
	"\x8B\xF9\x4C\x89\x60\x20\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x4C"
	"\x8B\x50\x18\x49\x83\xC2\x20\x4C\x89\x94\x24\x80\x00\x00\x00\x4D"
	"\x8B\x22\x4C\x89\x64\x24\x78\x4D\x3B\xE2\x0F\x84\x78\x01\x00\x00"
	"\x4C\x89\x6C\x24\x30\x8D\x7D\x04\x41\xBB\xFF\xFF\x00\x00\x66\x90"
	"\x4D\x8B\x44\x24\x50\x33\xD2\x45\x0F\xB7\x4C\x24\x48\x0F\x1F\x00"
	"\x41\x0F\xB6\x08\x4D\x8D\x40\x01\xC1\xCA\x0D\x8B\xC2\x48\x03\xC1"
	"\x80\xF9\x61\x48\x8D\x50\xE0\x48\x0F\x42\xD0\x66\x45\x03\xCB\x75"
	"\xDF\x81\xFA\x5B\xBC\x4A\x6A\x0F\x85\xFB\x00\x00\x00\x4D\x8B\x4C"
	"\x24\x20\x41\xBC\xFF\xFF\x00\x00\x49\x63\x41\x3C\x46\x8B\xAC\x08"
	"\x88\x00\x00\x00\x4D\x03\xE9\x45\x8B\x5D\x20\x41\x8B\x5D\x24\x4D"
	"\x03\xD9\x45\x8B\x55\x18\x49\x03\xD9\x0F\x1F\x80\x00\x00\x00\x00"
	"\x45\x85\xD2\x0F\x84\xA7\x00\x00\x00\x41\x8B\x13\x49\x03\xD1\x33"
	"\xC0\x0F\xB6\x0A\x0F\x1F\x40\x00\x0F\x1F\x84\x00\x00\x00\x00\x00"
	"\xC1\xC8\x0D\x48\x8D\x52\x01\x0F\xBE\xC9\x03\xC1\x0F\xB6\x0A\x84"
	"\xC9\x75\xED\x3D\xA4\x4E\x0E\xEC\x74\x15\x3D\xAA\xFC\x0D\x7C\x74"
	"\x0E\x3D\xA0\xD5\xC9\x4D\x74\x07\x3D\xAC\x33\x06\x03\x75\x4D\x41"
	"\x8B\x55\x1C\x44\x0F\xB7\x03\x49\x03\xD1\x3D\xA4\x4E\x0E\xEC\x75"
	"\x09\x46\x8B\x34\x82\x4D\x03\xF1\xEB\x2E\x3D\xAA\xFC\x0D\x7C\x75"
	"\x09\x46\x8B\x3C\x82\x4D\x03\xF9\xEB\x1E\x3D\xA0\xD5\xC9\x4D\x75"
	"\x09\x42\x8B\x2C\x82\x49\x03\xE9\xEB\x0E\x3D\xAC\x33\x06\x03\x75"
	"\x07\x42\x8B\x34\x82\x49\x03\xF1\x66\x41\x03\xFC\x49\x83\xC3\x04"
	"\x48\x83\xC3\x02\x41\xFF\xCA\x66\x85\xFF\x0F\x85\x50\xFF\xFF\xFF"
	"\x4C\x8B\x64\x24\x78\xBF\x04\x00\x00\x00\x4C\x8B\x94\x24\x80\x00"
	"\x00\x00\x41\xBB\xFF\xFF\x00\x00\x4D\x85\xF6\x74\x0F\x4D\x85\xFF"
	"\x74\x0A\x48\x85\xED\x74\x05\x48\x85\xF6\x75\x12\x4D\x8B\x24\x24"
	"\x4C\x89\x64\x24\x78\x4D\x3B\xE2\x0F\x85\xA2\xFE\xFF\xFF\x48\x8B"
	"\x7C\x24\x70\x4C\x8B\x6C\x24\x30\x4C\x8B\xA4\x24\x88\x00\x00\x00"
	"\x48\x89\x37\x4D\x85\xF6\x0F\x84\x82\x00\x00\x00\x4D\x85\xFF\x74"
	"\x7D\x48\x85\xED\x74\x78\x48\x85\xF6\x74\x73\x48\x8D\x4F\x08\xC7"
	"\x87\x10\x02\x00\x00\x26\x4E\x00\x00\x41\xFF\xD6\x48\x8B\xD8\x48"
	"\x85\xC0\x74\x4E\x48\x8D\x54\x24\x20\xC7\x87\x10\x02\x00\x00\x28"
	"\x4E\x00\x00\x48\x8B\xC8\x41\xFF\xD7\x48\x85\xC0\x74\x23\xC7\x87"
	"\x10\x02\x00\x00\x2A\x4E\x00\x00\xFF\xD0\x89\x87\x10\x02\x00\x00"
	"\x85\xC0\x75\x17\x48\x83\xC4\x38\x41\x5F\x41\x5E\x5F\x5E\x5D\x5B"
	"\xC3\xC7\x87\x10\x02\x00\x00\x29\x4E\x00\x00\x48\x8B\xCB\xFF\xD5"
	"\xEB\x16\xC7\x87\x10\x02\x00\x00\x27\x4E\x00\x00\xEB\x0A\xC7\x87"
	"\x10\x02\x00\x00\x23\x4E\x00\x00\xB8\x01\x00\x00\x00\x48\x83\xC4"
	"\x38\x41\x5F\x41\x5E\x5F\x5E\x5D\x5B\xC3";

static const SIZE_T x64ShellcodeSize = sizeof(x64Shellcode) - 1;

static USHORT GetProcessArch(HANDLE hProcess);
static HANDLE WINAPI MyCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags);
static BOOL CheckWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion,
	WORD wServicePackMajor, WORD wServicePackMinor, int op);
static BOOL JoinModulePathWithFileName(HINSTANCE hModule, const WCHAR* pszFileName, WCHAR* pJoinedPath);

// hProcess needs:
// PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
// PROCESS_QUERY_INFORMATION | SYNCHRONIZE

DWORD DllInject(HANDLE hProcess, HINSTANCE hDllInst, DWORD dwTimeout)
{
	const BYTE* pShellcode;
	SIZE_T nShellcodeSize;
	SIZE_T nPreShellcodeSize;
	const WCHAR* pDllFileName;
#ifndef _WIN64
	BOOL bWow64ToNative = FALSE;
#endif // _WIN64

	switch (GetProcessArch(hProcess))
	{
	case IMAGE_FILE_MACHINE_I386:
		pShellcode = x32Shellcode;
		nShellcodeSize = x32ShellcodeSize;
		nPreShellcodeSize = preX32ShellcodeSize;
		pDllFileName = INJECT_DLL_FILE_NAME_32;
		break;

	case IMAGE_FILE_MACHINE_AMD64:
		pShellcode = x64Shellcode;
		nShellcodeSize = x64ShellcodeSize;
		nPreShellcodeSize = preX64ShellcodeSize;
		pDllFileName = INJECT_DLL_FILE_NAME_64;
#ifndef _WIN64
		bWow64ToNative = TRUE;
#endif // _WIN64
		break;

	default:
		return EXE_ERR_UNSUPPORTED_ARCH;
	}

	LOAD_LIBRARY_REMOTE_DATA RemoteData;
	size_t cbDataSize = sizeof(LOAD_LIBRARY_REMOTE_DATA);
	HANDLE hRemoteThread;
	void* pRemoteCode;
	void* pRemoteData;
	DWORD dwError = 0;

	SIZE_T cbCodeSizeAligned = (nShellcodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

	RemoteData.dw64VirtualFree = 0;
	if (!JoinModulePathWithFileName(hDllInst, pDllFileName, RemoteData.szDllName))
	{
		return EXE_ERR_DLL_PATH_ERROR;
	}
	RemoteData.dwError = INJ_ERR_BEFORE_RUN; // in case the injected code fails

	// Allocate enough memory in the remote process's address space
	// to hold the shellcode and the data struct.
	pRemoteCode = VirtualAllocEx(hProcess, NULL, cbCodeSizeAligned + cbDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteCode)
	{
		BOOL bFreeMemory = TRUE;

		// Write our shellcode into the remote process.
		if (WriteProcessMemory(hProcess, pRemoteCode, pShellcode, nShellcodeSize, NULL))
		{
			// Write a copy of our struct to the remote process.
			pRemoteData = (BYTE*)pRemoteCode + cbCodeSizeAligned;
			if (WriteProcessMemory(hProcess, pRemoteData, &RemoteData, cbDataSize, NULL))
			{
#ifndef _WIN64
				if (bWow64ToNative)
				{
					hRemoteThread = (HANDLE)MyCreateRemoteThread64(
						(DWORD64)hProcess, (DWORD64)(LPTHREAD_START_ROUTINE)pRemoteCode, (DWORD64)pRemoteData);
				}
				else
#endif // _WIN64
				{
					// Create the remote thread.
					//hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
					//	(LPTHREAD_START_ROUTINE)pRemoteCode, pRemoteData, 0, NULL);
					hRemoteThread = MyCreateRemoteThread(hProcess, NULL,
						(LPTHREAD_START_ROUTINE)pRemoteCode, pRemoteData, 0);
				}
				if (hRemoteThread)
				{
					// Remote thread created, it will free the memory.
					bFreeMemory = FALSE;

					CloseHandle(hRemoteThread);
				}
				else
				{
					LOG(L"MyCreateRemoteThread failed with error %u", GetLastError());
					dwError = EXE_ERR_CREATE_REMOTE_THREAD;
				}
			}
			else
			{
				LOG(L"WriteProcessMemory failed with error %u", GetLastError());
				dwError = EXE_ERR_WRITE_PROC_MEM;
			}
		}
		else
		{
			LOG(L"WriteProcessMemory failed with error %u", GetLastError());
			dwError = EXE_ERR_WRITE_PROC_MEM;
		}

		if (bFreeMemory)
			VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
	}
	else
	{
		LOG(L"VirtualAllocEx failed with error %u", GetLastError());
		dwError = EXE_ERR_VIRTUAL_ALLOC;
	}

	return dwError;
}

static USHORT GetProcessArch(HANDLE hProcess)
{
	// For now, only IMAGE_FILE_MACHINE_I386 and IMAGE_FILE_MACHINE_AMD64.
	// TODO: Use IsWow64Process2 if available.

#ifndef _WIN64
	SYSTEM_INFO siSystemInfo;
	GetNativeSystemInfo(&siSystemInfo);
	if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		// 32-bit machine, only one option.
		return IMAGE_FILE_MACHINE_I386;
	}
#endif // _WIN64

	BOOL bIsWow64Process;
	if (IsWow64Process(hProcess, &bIsWow64Process) && bIsWow64Process)
	{
		return IMAGE_FILE_MACHINE_I386;
	}

	return IMAGE_FILE_MACHINE_AMD64;
}

//
// Based on: 
// http://securityxploded.com/ntcreatethreadex.php
//
static HANDLE WINAPI MyCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags)
{
	static NTSTATUS(WINAPI * pNtCreateThreadEx)(
		OUT PHANDLE hThread,
		IN ACCESS_MASK DesiredAccess,
		IN LPVOID ObjectAttributes,
		IN HANDLE ProcessHandle,
		IN LPTHREAD_START_ROUTINE lpStartAddress,
		IN LPVOID lpParameter,
		IN BOOL CreateSuspended,
		IN ULONG_PTR StackZeroBits,
		IN ULONG_PTR SizeOfStackCommit,
		IN ULONG_PTR SizeOfStackReserve,
		OUT LPVOID lpBytesBuffer
	) = (void*)-1;

	if (pNtCreateThreadEx == (void*)-1) // lazy initialization
	{
		pNtCreateThreadEx = NULL;

		if (CheckWindowsVersion(6, 0, 0, 0, VER_GREATER_EQUAL) &&
			!CheckWindowsVersion(6, 2, 0, 0, VER_GREATER_EQUAL)) // Windows Vista and 7
		{
			HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
			if (hNtdll)
				*(void**)&pNtCreateThreadEx = GetProcAddress(hNtdll, "NtCreateThreadEx");
		}
	}

	if (pNtCreateThreadEx)
	{
		HANDLE hThread;
		NTSTATUS result;
		ULONG_PTR bOutBuffer1[2];
		ULONG_PTR bOutBuffer2[1];
		struct {
			ULONG_PTR Size;
			ULONG_PTR Unknown1;
			ULONG_PTR nBuf1Size;
			void* pBuf1;
			ULONG_PTR Unknown2;
			ULONG_PTR Unknown3;
			ULONG_PTR nBuf2Size;
			void* pBuf2;
			ULONG_PTR Unknown4;
		} param = { sizeof(param), 0x10003, sizeof(ULONG_PTR) * 2, bOutBuffer1, 0, 0x10004, sizeof(ULONG_PTR), bOutBuffer2, 0 };

		result = pNtCreateThreadEx(&hThread, 0x1FFFFF, lpThreadAttributes,
			hProcess, lpStartAddress, lpParameter, (dwCreationFlags & CREATE_SUSPENDED) ? TRUE : FALSE, 0, 0, 0, &param);
		if (result < 0)
		{
			SetLastError(LsaNtStatusToWinError(result));
			return NULL;
		}

		return hThread;
	}

	return CreateRemoteThread(hProcess, lpThreadAttributes, 0, lpStartAddress, lpParameter, dwCreationFlags, NULL);
}

//
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms725491%28v=vs.85%29.aspx
//
static BOOL CheckWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion,
	WORD wServicePackMajor, WORD wServicePackMinor, int op)
{
	// Initialize the OSVERSIONINFOEX structure
	OSVERSIONINFOEX osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osvi.dwMajorVersion = dwMajorVersion;
	osvi.dwMinorVersion = dwMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;
	osvi.wServicePackMinor = wServicePackMinor;

	// Initialize the type mask
	DWORD dwTypeMask = VER_MAJORVERSION | VER_MINORVERSION |
		VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;

	// Initialize the condition mask
	DWORDLONG dwlConditionMask = 0;

	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);
	VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, op);
	VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, op);

	// Perform the test
	return VerifyVersionInfo(&osvi, dwTypeMask, dwlConditionMask);
}

static BOOL JoinModulePathWithFileName(HINSTANCE hModule, const WCHAR* pszFileName, WCHAR* pJoinedPath)
{
	int i = GetModuleFileName(hModule, pJoinedPath, MAX_PATH);
	if (i == 0 || i == MAX_PATH)
	{
		LOG(L"GetModuleFileName failed, i is %d and GetLastError() is %u", i, GetLastError());
		return FALSE;
	}

	while (i-- && pJoinedPath[i] != L'\\');

	if (i + 1 + wcslen(pszFileName) + 1 > MAX_PATH)
	{
		LOG(L"JoinModulePathWithFileName failed, file name too long");
		return FALSE;
	}

	lstrcpy(&pJoinedPath[i + 1], pszFileName);
	return TRUE;
}
