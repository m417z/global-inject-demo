#include "stdafx.h"
#include "new_process_injector.h"
#include "session_private_namespace.h"
#include "dll_inject.h"
#include "functions.h"
#include "logger.h"

// This static pointer is used in the hook procedure.
// As a result, only one instance of the class can be used at any given time.
NewProcessInjector* volatile NewProcessInjector::pThis;

NewProcessInjector::NewProcessInjector(HANDLE hSessionManagerProcess) :
	hSessionManagerProcess(hSessionManagerProcess)
{
	if (_InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(&pThis), this, nullptr)) {
		throw std::logic_error("NewProcessInjector - only one instance is supported at any given time");
	}

	bool createProcessInternalWHooked = false;

	// Try kernelbase.dll first.
	HMODULE hKernelBase = GetModuleHandle(L"kernelbase.dll");
	if (hKernelBase) {
		CreateProcessInternalW_t pCreateProcessInternalW =
			reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(hKernelBase, "CreateProcessInternalW"));
		if (pCreateProcessInternalW) {
			if (MH_CreateHook(pCreateProcessInternalW, CreateProcessInternalW_Hook,
				reinterpret_cast<void**>(&originalCreateProcessInternalW)) == MH_OK) {
				MH_QueueEnableHook(pCreateProcessInternalW);
				createProcessInternalWHooked = true;
			}
		}
	}

	if (!createProcessInternalWHooked) {
		// Try kernel32.dll next.
		HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
		if (hKernel32) {
			CreateProcessInternalW_t pCreateProcessInternalW =
				reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(hKernel32, "CreateProcessInternalW"));
			if (pCreateProcessInternalW) {
				if (MH_CreateHook(pCreateProcessInternalW, CreateProcessInternalW_Hook,
					reinterpret_cast<void**>(&originalCreateProcessInternalW)) == MH_OK) {
					MH_QueueEnableHook(pCreateProcessInternalW);
					createProcessInternalWHooked = true;
				}
			}
		}
	}

	if (!createProcessInternalWHooked) {
		LOG(L"Failed to hook CreateProcessInternalW");
	}
}

NewProcessInjector::~NewProcessInjector()
{
	while (nHookProcCallCounter > 0) {
		Sleep(10);
	}

	_InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(&pThis), nullptr, this);
}

BOOL WINAPI NewProcessInjector::CreateProcessInternalW_Hook(
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
	DWORD_PTR unknown)
{
	InterlockedIncrement(&pThis->nHookProcCallCounter);

	BOOL bRet;

	__try {
		DWORD dwNewCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

		bRet = pThis->originalCreateProcessInternalW(
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

		if (bRet) {
			HandleCreatedProcess(lpProcessInformation);

			if (!(dwCreationFlags & CREATE_SUSPENDED)) {
				ResumeThread(lpProcessInformation->hThread);
			}

			VERBOSE(L"New process %u from CreateProcessInternalW(\"%s\", \"%s\")",
				lpProcessInformation->dwProcessId,
				lpApplicationName ? lpApplicationName : L"(NULL)",
				lpCommandLine ? lpCommandLine : L"(NULL)");
		}

		SetLastError(dwError);
	}
	__finally {
		InterlockedDecrement(&pThis->nHookProcCallCounter);
	}

	return bRet;
}

void NewProcessInjector::HandleCreatedProcess(LPPROCESS_INFORMATION lpProcessInformation)
{
	try {
		wil::unique_mutex_nothrow mutex(CreateProcessInitAPCMutex(pThis->hSessionManagerProcess, lpProcessInformation->dwProcessId, FALSE));
		if (GetLastError() == ERROR_ALREADY_EXISTS) {
			// Make sure the main thread doesn't begin execution before the
			// APC is queued.
			THROW_LAST_ERROR_IF(WaitForSingleObject(mutex.get(), INFINITE) == WAIT_FAILED);
			ReleaseMutex(mutex.get());
			return;
		}

		DllInject::DllInject(lpProcessInformation->hProcess, lpProcessInformation->hThread, pThis->hSessionManagerProcess, mutex.get());
		VERBOSE(L"DllInject succeeded for new process %u", lpProcessInformation->dwProcessId);
	}
	catch (const std::exception& e) {
		LOG(L"Error for new process %u: %S", lpProcessInformation->dwProcessId, e.what());
	}
}

HANDLE NewProcessInjector::CreateProcessInitAPCMutex(HANDLE sessionManagerProcess, DWORD processId, BOOL initialOwner)
{
	DWORD dwSessionManagerProcessId = GetProcessId(sessionManagerProcess);
	THROW_LAST_ERROR_IF(dwSessionManagerProcessId == 0);

	wil::unique_private_namespace_close privateNamespace;
	if (dwSessionManagerProcessId != GetCurrentProcessId()) {
		privateNamespace = SessionPrivateNamespace::Open(dwSessionManagerProcessId);
	}

	WCHAR szMutexName[SessionPrivateNamespace::PrivateNamespaceMaxLen + sizeof("\\ProcessInitAPCMutex-pid=1234567890")];
	int mutexNamePos = SessionPrivateNamespace::MakeName(szMutexName, dwSessionManagerProcessId);
	swprintf_s(szMutexName + mutexNamePos, ARRAYSIZE(szMutexName) - mutexNamePos,
		L"\\ProcessInitAPCMutex-pid=%u", processId);

	wil::unique_hlocal secDesc;
	THROW_IF_WIN32_BOOL_FALSE(GetFullAccessSecurityDescriptor(&secDesc, nullptr));

	SECURITY_ATTRIBUTES secAttr = { sizeof(SECURITY_ATTRIBUTES) };
	secAttr.lpSecurityDescriptor = secDesc.get();
	secAttr.bInheritHandle = FALSE;

	wil::unique_mutex_nothrow mutex(CreateMutex(&secAttr, initialOwner, szMutexName));
	THROW_LAST_ERROR_IF_NULL(mutex);

	return mutex.release();
}
