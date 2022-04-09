#include <windows.h>
#include "new_process_injector.h"
#include "MinHook/MinHook.h"
#include "dll_inject.h"
#include "logger.h"

extern HINSTANCE hDllInst;

static volatile long nHookProcCallCounter = 0;

#define CREATE_FUNCTION_HOOK(func_name) \
	MH_CreateHook(func_name, func_name##_Hook, (void **)&Original##func_name)

#define CREATE_FUNCTION_HOOK_P(func_name) \
	MH_CreateHook(p##func_name, func_name##_Hook, (void **)&Original##func_name)

#define DEFINE_HOOK_FUNCTION(func_name, ret_type, calling_conv, ...) \
	typedef ret_type(calling_conv *func_name##_type)(__VA_ARGS__); \
	static func_name##_type Original##func_name; \
	\
	static ret_type calling_conv func_name##_Hook(__VA_ARGS__) \
	{ \
		InterlockedIncrement(&nHookProcCallCounter); \
		\
		__try \
		{

#define END_HOOK_FUNCTION() \
		} \
		__finally \
		{ \
			InterlockedDecrement(&nHookProcCallCounter); \
		} \
	}

static BOOL NewProcessInject(HANDLE hProcess);

DEFINE_HOOK_FUNCTION(CreateProcessInternalW, BOOL, WINAPI,
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	DWORD_PTR unknown
)
{
	DWORD dwNewCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

	BOOL bRet = OriginalCreateProcessInternalW(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwNewCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		unknown
	);

	DWORD dwError = GetLastError();

	if(bRet)
	{
		NewProcessInject(lpProcessInformation->hProcess);

		if(!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(lpProcessInformation->hThread);
	}

	LOG(L"CreateProcessInternalW(\"%s\", \"%s\") returned %d",
		lpApplicationName ? lpApplicationName : L"(NULL)", lpCommandLine ? lpCommandLine : L"(NULL)", bRet);

	SetLastError(dwError);

	return bRet;
}
END_HOOK_FUNCTION()

BOOL InitNewProcessInjector(void)
{
	LOG(L"Running InitNewProcessInjector");

	BOOL bCreateProcessInternalWHooked = FALSE;

	// Try kernelbase.dll first.

	HMODULE hKernelBase = GetModuleHandle(L"kernelbase.dll");
	if(hKernelBase)
	{
		CreateProcessInternalW_type pCreateProcessInternalW = (CreateProcessInternalW_type)GetProcAddress(hKernelBase, "CreateProcessInternalW");
		if(pCreateProcessInternalW)
		{
			if(CREATE_FUNCTION_HOOK_P(CreateProcessInternalW) == MH_OK)
				bCreateProcessInternalWHooked = TRUE;
		}
	}

	if(!bCreateProcessInternalWHooked)
	{
		// Try kernel32.dll next.

		HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
		if(hKernel32)
		{
			CreateProcessInternalW_type pCreateProcessInternalW = (CreateProcessInternalW_type)GetProcAddress(hKernel32, "CreateProcessInternalW");
			if(pCreateProcessInternalW)
			{
				if(CREATE_FUNCTION_HOOK_P(CreateProcessInternalW) == MH_OK)
					bCreateProcessInternalWHooked = TRUE;
			}
		}
	}

	if(!bCreateProcessInternalWHooked)
		LOG(L"Failed to hook CreateProcessInternalW");

	return TRUE;
}

void UninitNewProcessInjector(void)
{
	while(nHookProcCallCounter > 0)
		Sleep(10);
}

static BOOL NewProcessInject(HANDLE hProcess)
{
	return DllInject(hProcess, hDllInst, 1000) == 0;
}
