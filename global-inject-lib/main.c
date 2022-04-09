#include <windows.h>
#include "MinHook/MinHook.h"
#include "wow64ext/wow64ext.h"
#include "dll_inject.h"
#include "new_process_injector.h"
#include "all_processes_injector.h"
#include "process_handler.h"
#include "waiting_thread.h"
#include "logger.h"

HINSTANCE hDllInst;

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		hDllInst = hinstDLL;

#ifndef _WIN64
		Wow64ExtInitialize();
#endif // _WIN64
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

// Exported
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:InjectInit=_InjectInit@0")
#else
__declspec(dllexport)
#endif

DWORD __stdcall InjectInit(void)
{
	LOG(L"Running InjectInit");

	static volatile BOOL bInitCalled = FALSE;

	// Make sure this function is called only once
	if(InterlockedExchange((long *)&bInitCalled, TRUE))
	{
		LOG(L"bInitCalled is already set to TRUE");
		return LIB_ERR_INIT_ALREADY_CALLED;
	}

	MH_STATUS status = MH_Initialize();
	if(status != MH_OK)
	{
		LOG(L"MH_Initialize failed with %d", status);
		return LIB_ERR_MINHOOK_FAILED;
	}

	InitNewProcessInjector();
	SetupProcessHandler();

	status = MH_EnableHook(MH_ALL_HOOKS);
	if(status != MH_OK)
		LOG(L"MH_EnableHook failed with %d", status);

	CreateWaitingThread();

	return 0;
}

// Exported
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:SetGlobalHook=_SetGlobalHook@0")
#else
__declspec(dllexport)
#endif

BOOL __stdcall SetGlobalHook(void)
{
	LOG(L"Running SetGlobalHook");

	return InjectDllToAllProcesses(hDllInst);
}
