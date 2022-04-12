#include "stdafx.h"
#include "all_processes_injector.h"
#include "customization_session.h"
#include "logger.h"

HINSTANCE g_hDllInst;

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason) {
	case DLL_PROCESS_ATTACH:
		g_hDllInst = hinstDLL;

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
BOOL InjectInit(BOOL bRunningFromAPC, HANDLE hSessionManagerProcess, HANDLE hSessionMutex)
{
	VERBOSE(L"Running InjectInit");

	if (!CustomizationSession::Start(bRunningFromAPC, hSessionManagerProcess, hSessionMutex)) {
		return FALSE;
	}

	return TRUE;
}

// Exported
HANDLE GlobalHookSessionStart()
{
	VERBOSE(L"Running GlobalHookSessionStart");

	try {
		return static_cast<HANDLE>(new AllProcessesInjector());
	}
	catch (const std::exception& e) {
		LOG(L"%S", e.what());
	}

	return nullptr;
}

// Exported
int GlobalHookSessionHandleNewProcesses(HANDLE hSession)
{
	VERBOSE(L"Running GlobalHookSessionHandleNewProcesses");

	auto allProcessInjector = static_cast<AllProcessesInjector*>(hSession);
	return allProcessInjector->InjectIntoNewProcesses();
}

// Exported
BOOL GlobalHookSessionEnd(HANDLE hSession)
{
	VERBOSE(L"Running GlobalHookSessionEnd");

	auto allProcessInjector = static_cast<AllProcessesInjector*>(hSession);
	delete allProcessInjector;

	return TRUE;
}
