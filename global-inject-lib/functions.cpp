#include "functions.h"

#include <ntsecapi.h>
#include <sddl.h>
#include <tlhelp32.h>

#include <wow64ext/wow64ext.h>

//
// Based on:
// http://securityxploded.com/ntcreatethreadex.php
//
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, USHORT targetProcessArch)
{
	#ifndef _WIN64
	if (targetProcessArch == IMAGE_FILE_MACHINE_AMD64) {
		// WOW64 to x64 native, use heaven's gate.
		return (HANDLE)CreateRemoteThread64(
			HANDLE_TO_DWORD64(hProcess), PTR_TO_DWORD64(lpStartAddress), PTR_TO_DWORD64(lpParameter));
	}
	#endif // _WIN64

	using NtCreateThreadEx_t = NTSTATUS(WINAPI*)(
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
		);

	static NtCreateThreadEx_t pNtCreateThreadEx = []() {
		// Only needed for Windows Vista and 7.
		if (CheckWindowsVersion(6, 0, 0, 0, VER_GREATER_EQUAL) &&
			!CheckWindowsVersion(6, 2, 0, 0, VER_GREATER_EQUAL)) {
			HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
			if (hNtdll) {
				return (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
			}
		}

		return (NtCreateThreadEx_t)nullptr;
	}();

	LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;
	DWORD dwCreationFlags = 0;

	if (pNtCreateThreadEx) {
		HANDLE hThread;
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

		NTSTATUS result = pNtCreateThreadEx(&hThread, 0x1FFFFF, lpThreadAttributes,
			hProcess, lpStartAddress, lpParameter, (dwCreationFlags & CREATE_SUSPENDED) ? TRUE : FALSE, 0, 0, 0, &param);
		if (result < 0) {
			SetLastError(LsaNtStatusToWinError(result));
			return nullptr;
		}

		return hThread;
	}

	return CreateRemoteThread(hProcess, lpThreadAttributes, 0, lpStartAddress, lpParameter, dwCreationFlags, nullptr);
}

//
// Reference: https://repnz.github.io/posts/apc/wow64-user-apc/
//
ULONG64 EncodeWow64ApcRoutine(ULONG64 ApcRoutine)
{
	return (ULONG64)((-(INT64)ApcRoutine) << 2);
}

//
// Reference: https://repnz.github.io/posts/apc/user-apc/
//
BOOL MyQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData, USHORT targetProcessArch)
{
	#ifndef _WIN64
	if (targetProcessArch == IMAGE_FILE_MACHINE_AMD64) {
		// WOW64 to x64 native, use heaven's gate.
		//
		// "Microsoft added a validation to prevent a programming error:
		// If you try to queue an APC from a 32 bit process to a 64 bit
		// process and you use a 32 bit address, you'll get this status code:
		// [...] STATUS_INVALID_HANDLE"
		// https://repnz.github.io/posts/apc/wow64-user-apc/
		return NtQueueApcThread64(
			HANDLE_TO_DWORD64(hThread), PTR_TO_DWORD64(pfnAPC), (DWORD64)dwData, 0, 0);
	}
	#endif // _WIN64

	using NtQueueApcThread_t = DWORD(WINAPI*)(
		IN HANDLE ThreadHandle,
		IN PVOID ApcDispatchRoutine,
		IN ULONG_PTR SystemArgument1,
		IN ULONG_PTR SystemArgument2,
		IN ULONG_PTR SystemArgument3
		);

	static NtQueueApcThread_t pNtQueueApcThread = []() {
		HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
		if (hNtdll) {
			return (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");
		}

		return (NtQueueApcThread_t)nullptr;
	}();

	if (!pNtQueueApcThread) {
		SetLastError(ERROR_PROC_NOT_FOUND);
		return FALSE;
	}

	#ifdef _WIN64
	if (targetProcessArch == IMAGE_FILE_MACHINE_I386) {
		// x64 native to WOW64, encode address.
		pfnAPC = (PAPCFUNC)EncodeWow64ApcRoutine((ULONG64)pfnAPC);
	}
	#endif // _WIN64

	NTSTATUS result = pNtQueueApcThread(hThread, pfnAPC, dwData, 0, 0);
	if (result < 0) {
		SetLastError(LsaNtStatusToWinError(result));
		return FALSE;
	}

	return TRUE;
}
