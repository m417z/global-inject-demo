#include <windows.h>
#include <sddl.h>
#include "waiting_thread.h"
#include "MinHook/MinHook.h"
#include "new_process_injector.h"
#include "process_handler.h"
#include "logger.h"

#define WAITING_EVENT_NAME L"Global\\GlobalHookEvent.{B89D7EDC-04A4-49AF-9BD2-8598D6CB1D34}"

extern HINSTANCE hDllInst;

static PSECURITY_DESCRIPTOR MakeAllowAllSecurityDescriptor(void);
static DWORD WINAPI WaitingThreadProc(LPVOID lpParameter);

BOOL CreateWaitingThread(void)
{
	LOG(L"Running CreateWaitingThread");

	PSECURITY_DESCRIPTOR pSecDesc = MakeAllowAllSecurityDescriptor();
	if(!pSecDesc)
	{
		LOG(L"MakeAllowAllSecurityDescriptor failed with error %u", GetLastError());
		return FALSE;
	}

	SECURITY_ATTRIBUTES SecAttr;
	SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecAttr.lpSecurityDescriptor = pSecDesc;
	SecAttr.bInheritHandle = FALSE;

	HANDLE hEvent = CreateEvent(&SecAttr, TRUE, FALSE, WAITING_EVENT_NAME);
	if(!hEvent)
		LOG(L"CreateEvent failed with error %u", GetLastError());

	LocalFree(pSecDesc);

	if(!hEvent)
		return FALSE;

	HANDLE hThread = CreateThread(NULL, 0, WaitingThreadProc, (void *)hEvent, 0, NULL);
	if(!hThread)
	{
		CloseHandle(hEvent);
		LOG(L"CreateThread failed with error %u", GetLastError());
		return FALSE;
	}

	CloseHandle(hThread);
	return TRUE;
}

//
// From http://blogs.msdn.com/b/winsdk/archive/2009/11/10/access-denied-on-a-mutex.aspx
//
static PSECURITY_DESCRIPTOR MakeAllowAllSecurityDescriptor(void)
{
	const WCHAR *pszStringSecurityDescriptor;
	PSECURITY_DESCRIPTOR pSecDesc;

	pszStringSecurityDescriptor = L"D:(A;;GA;;;WD)(A;;GA;;;AN)S:(ML;;NW;;;ME)";

	if(!ConvertStringSecurityDescriptorToSecurityDescriptor(pszStringSecurityDescriptor, SDDL_REVISION_1, &pSecDesc, NULL))
		return NULL;

	return pSecDesc;
}

static DWORD WINAPI WaitingThreadProc(LPVOID lpParameter)
{
	HANDLE hEvent = (HANDLE)lpParameter;

	if(WaitForSingleObject(hEvent, INFINITE) != WAIT_OBJECT_0)
		LOG(L"WaitForSingleObject failed with error %u", GetLastError());

	CloseHandle(hEvent);

	MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
	if(status != MH_OK)
		LOG(L"MH_DisableHook failed with status %d", status);

	UninitNewProcessInjector();
	DestroyProcessHandler();

	status = MH_Uninitialize();
	if(status != MH_OK)
		LOG(L"MH_Uninitialize failed with status %d", status);

	FreeLibraryAndExitThread(hDllInst, 0);
}
