#include "stdafx.h"
#include "customization_session.h"
#include "session_private_namespace.h"
#include "logger.h"

extern HINSTANCE g_hDllInst;

namespace
{
	typedef int (WINAPI* MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

	MESSAGEBOXW pOriginalMessageBoxW;

	int WINAPI MessageBoxWHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
	{
		static int counter = 0;
		counter++;

		WCHAR newText[1025];
		wsprintf(newText, L"Global injection and hooking demo!\n\n%s", lpText);

		WCHAR newTitle[1025];
		wsprintf(newTitle, L"[%d] %s", counter, lpCaption);

		return pOriginalMessageBoxW(hWnd, newText, newTitle, uType);
	}

	MH_STATUS InitCustomizationHooks()
	{
		MH_STATUS status = MH_CreateHook(MessageBoxW, (void*)MessageBoxWHook, (void**)&pOriginalMessageBoxW);
		if (status == MH_OK) {
			status = MH_QueueEnableHook(MessageBoxW);
		}

		return status;
	}
}

bool CustomizationSession::Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	auto instance = new (std::nothrow) CustomizationSession();
	if (!instance) {
		LOG(L"Allocation of CustomizationSession failed");
		return false;
	}

	if (!instance->StartAllocated(runningFromAPC, sessionManagerProcess, sessionMutex)) {
		delete instance;
		return false;
	}

	// Instance will free itself.
	return true;
}

bool CustomizationSession::StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	// Create the session semaphore. This will block the library if another instance
	// (from another session manager process) is already injected and its customization session is active.
	WCHAR szSemaphoreName[sizeof("CustomizationSessionSemaphore-pid=1234567890")];
	swprintf_s(szSemaphoreName, L"CustomizationSessionSemaphore-pid=%u", GetCurrentProcessId());

	HRESULT hr = m_sessionSemaphore.create(1, 1, szSemaphoreName);
	if (FAILED(hr)) {
		LOG(L"Semaphore creation failed with error %08X", hr);
		return false;
	}

	m_sessionSemaphoreLock = m_sessionSemaphore.acquire();

	if (WaitForSingleObject(sessionManagerProcess, 0) != WAIT_TIMEOUT) {
		VERBOSE(L"Session manager process is no longer running");
		return false;
	}

	if (!InitSession(runningFromAPC, sessionManagerProcess)) {
		return false;
	}

	if (runningFromAPC) {
		// Create a new thread for us to allow the program's main thread to run.
		try {
			// Note: Before creating the thread, the CRT/STL bumps the
			// reference count of the module, something a plain CreateThread
			// doesn't do.
			std::thread thread(&CustomizationSession::RunAndDeleteThis, this,
				sessionManagerProcess, sessionMutex);
			thread.detach();
		}
		catch (const std::exception& e) {
			LOG(L"%S", e.what());
			UninitSession();
			return false;
		}
	}
	else {
		// No need to create a new thread, a dedicated thread was created for us
		// before injection.
		RunAndDeleteThis(sessionManagerProcess, sessionMutex);
	}

	return true;
}

bool CustomizationSession::InitSession(bool runningFromAPC, HANDLE sessionManagerProcess) noexcept
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK) {
		LOG(L"MH_Initialize failed with %d", status);
		return false;
	}

	if (runningFromAPC) {
		// No other threads should be running, skip thread freeze.
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_NONE_UNSAFE);
	}
	else {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	try {
		m_newProcessInjector.emplace(sessionManagerProcess);
	}
	catch (const std::exception& e) {
		LOG(L"InitSession failed: %S", e.what());
		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}

	status = InitCustomizationHooks();
	if (status != MH_OK) {
		LOG(L"InitCustomizationHooks failed with %d", status);
	}

	status = MH_ApplyQueued();
	if (status != MH_OK) {
		LOG(L"MH_ApplyQueued failed with %d", status);
	}

	if (runningFromAPC) {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	return true;
}

void CustomizationSession::RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	m_sessionManagerProcess.reset(sessionManagerProcess);

	if (sessionMutex) {
		m_sessionMutex.reset(sessionMutex);
	}

	// Prevent the system from displaying the critical-error-handler message box.
	// A message box like this was appearing while trying to load a dll in a
	// process with the ProcessSignaturePolicy mitigation, and it looked like this:
	// https://stackoverflow.com/q/38367847
	DWORD dwOldMode;
	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &dwOldMode);

	Run();

	SetThreadErrorMode(dwOldMode, nullptr);

	delete this;
}

void CustomizationSession::Run() noexcept
{
	DWORD waitResult = WaitForSingleObject(m_sessionManagerProcess.get(), INFINITE);
	if (waitResult != WAIT_OBJECT_0) {
		LOG(L"WaitForSingleObject returned %u, last error %u", waitResult, GetLastError());
	}

	VERBOSE(L"Uninitializing and freeing library");

	UninitSession();
}

void CustomizationSession::UninitSession() noexcept
{
	MH_STATUS status = MH_Uninitialize();
	if (status != MH_OK) {
		LOG(L"MH_Uninitialize failed with status %d", status);
	}

	m_newProcessInjector.reset();
}
