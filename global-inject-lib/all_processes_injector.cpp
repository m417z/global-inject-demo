#include "stdafx.h"
#include "all_processes_injector.h"
#include "session_private_namespace.h"
#include "dll_inject.h"
#include "functions.h"
#include "logger.h"

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

AllProcessesInjector::AllProcessesInjector()
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	THROW_LAST_ERROR_IF_NULL(hNtdll);

	NtGetNextProcess = (NtGetNextProcess_t)GetProcAddress(hNtdll, "NtGetNextProcess");
	THROW_LAST_ERROR_IF_NULL(NtGetNextProcess);

	NtGetNextThread = (NtGetNextThread_t)GetProcAddress(hNtdll, "NtGetNextThread");
	THROW_LAST_ERROR_IF_NULL(NtGetNextThread);

#ifdef _WIN64
	pRtlUserThreadStart = (DWORD64)GetProcAddress(hNtdll, "RtlUserThreadStart");
#else // !_WIN64
	SYSTEM_INFO siSystemInfo;
	GetNativeSystemInfo(&siSystemInfo);
	if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		// 32-bit machine.
		pRtlUserThreadStart = PTR_TO_DWORD64(GetProcAddress(hNtdll, "RtlUserThreadStart"));
	}
	else {
		DWORD64 hNtdll64 = GetModuleHandle64(L"ntdll.dll");
		if (hNtdll64 == 0) {
			THROW_WIN32(ERROR_MOD_NOT_FOUND);
		}

		pRtlUserThreadStart = GetProcAddress64(hNtdll64, "RtlUserThreadStart");
	}
#endif // _WIN64
	THROW_LAST_ERROR_IF(pRtlUserThreadStart == 0);

	appPrivateNamespace = SessionPrivateNamespace::Create(GetCurrentProcessId());
}

int AllProcessesInjector::InjectIntoNewProcesses() noexcept
{
	int count = 0;

	while (true) {
		// Note: If we don't have the required permissions, the process is skipped.
		HANDLE hNewProcess;
		NTSTATUS status = NtGetNextProcess(lastEnumeratedProcess.get(),
			SYNCHRONIZE | DllInject::ProcessAccess, 0, 0, &hNewProcess);
		if (!NT_SUCCESS(status)) {
			if (status != STATUS_NO_MORE_ENTRIES) {
				LOG(L"NtGetNextProcess error: %08X", status);
			}

			break;
		}

		lastEnumeratedProcess.reset(hNewProcess);

		if (WaitForSingleObject(hNewProcess, 0) == WAIT_OBJECT_0) {
			// Process is no longer alive.
			continue;
		}

		DWORD dwNewProcessId = GetProcessId(hNewProcess);
		if (dwNewProcessId == 0) {
			LOG(L"GetProcessId error: %u", GetLastError());
			continue;
		}

		try {
			InjectIntoNewProcess(hNewProcess, dwNewProcessId);
			count++;
		}
		catch (const std::exception& e) {
			LOG(L"InjectIntoNewProcess error for process %u: %S", dwNewProcessId, e.what());
		}
	}

	return count;
}

void AllProcessesInjector::InjectIntoNewProcess(HANDLE hProcess, DWORD dwProcessId)
{
	// We check whether the process began running or not. If it didn't, it's
	// supposed to have only one thread which has its instruction pointer at
	// RtlUserThreadStart. For other cases, we assume the main thread was
	// resumed.
	//
	// If the process didn't begin running, creating a remote thread might be
	// too early and unsafe. One known problem with this is with console apps -
	// if we trigger console initialization (KERNELBASE!ConsoleCommitState)
	// before the parent process notified csrss.exe (KERNELBASE!CsrClientCallServer),
	// csrss.exe returns an access denied error and the parent's CreateProcess
	// call fails.
	//
	// If the process is the current process, we skip this check since it
	// obviously began running, and we don't want to suspend the current thread
	// and cause a deadlock.

	wil::unique_process_handle suspendedThread;

	if (dwProcessId != GetCurrentProcessId()) {
		DWORD processAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | DllInject::ProcessAccess;

		wil::unique_process_handle thread1;
		THROW_IF_NTSTATUS_FAILED(NtGetNextThread(hProcess, nullptr, processAccess, 0, 0, &thread1));

		wil::unique_process_handle thread2;
		NTSTATUS status = NtGetNextThread(hProcess, thread1.get(), processAccess, 0, 0, &thread2);
		if (status == STATUS_NO_MORE_ENTRIES) {
			// Exactly one thread.
			DWORD previousSuspendCount = SuspendThread(thread1.get());
			THROW_LAST_ERROR_IF(previousSuspendCount == (DWORD)-1);

			if (previousSuspendCount == 0) {
				// The thread was already running.
				ResumeThread(thread1.get());
			}
			else {
				suspendedThread = std::move(thread1);
			}
		}
		else {
			THROW_IF_NTSTATUS_FAILED(status);
		}
	}

	if (suspendedThread) {
		auto suspendThreadCleanup = wil::scope_exit([&suspendedThread] {
			ResumeThread(suspendedThread.get());
		});

		bool threadNotStartedYet = false;

#ifdef _WIN64
		CONTEXT c;
		c.ContextFlags = CONTEXT_CONTROL;
		THROW_IF_WIN32_BOOL_FALSE(GetThreadContext(suspendedThread.get(), &c));
		if (c.Rip == pRtlUserThreadStart) {
			threadNotStartedYet = true;
		}
#else // !_WIN64
		SYSTEM_INFO siSystemInfo;
		GetNativeSystemInfo(&siSystemInfo);
		if (siSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
			// 32-bit machine.
			CONTEXT c;
			c.ContextFlags = CONTEXT_CONTROL;
			THROW_IF_WIN32_BOOL_FALSE(GetThreadContext(suspendedThread.get(), &c));
			if (c.Eip == pRtlUserThreadStart) {
				threadNotStartedYet = true;
			}
		}
		else {
			_CONTEXT64 c;
			c.ContextFlags = CONTEXT64_CONTROL;
			THROW_IF_WIN32_BOOL_FALSE(GetThreadContext64(suspendedThread.get(), &c));
			if (c.Rip == pRtlUserThreadStart) {
				threadNotStartedYet = true;
			}
		}
#endif // _WIN64

		if (threadNotStartedYet) {
			wil::unique_mutex_nothrow mutex(CreateProcessInitAPCMutex(dwProcessId, TRUE));
			if (GetLastError() == ERROR_ALREADY_EXISTS) {
				return; // APC was already created
			}

			auto mutexLock = mutex.ReleaseMutex_scope_exit();

			DllInject::DllInject(hProcess, suspendedThread.get(), GetCurrentProcess(), mutex.get());
			VERBOSE(L"DllInject succeeded for new process %u via APC", dwProcessId);

			return;
		}
	}

	wil::unique_mutex_nothrow mutex(OpenProcessInitAPCMutex(dwProcessId, SYNCHRONIZE));
	if (mutex) {
		return; // APC was already created
	}

	DllInject::DllInject(hProcess, nullptr, GetCurrentProcess(), nullptr);
	VERBOSE(L"DllInject succeeded for new process %u via a remote thread", dwProcessId);
}

HANDLE AllProcessesInjector::CreateProcessInitAPCMutex(DWORD processId, BOOL initialOwner)
{
	WCHAR szMutexName[SessionPrivateNamespace::PrivateNamespaceMaxLen + sizeof("\\ProcessInitAPCMutex-pid=1234567890")];
	int mutexNamePos = SessionPrivateNamespace::MakeName(szMutexName, GetCurrentProcessId());
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

HANDLE AllProcessesInjector::OpenProcessInitAPCMutex(DWORD processId, DWORD desiredAccess)
{
	WCHAR szMutexName[SessionPrivateNamespace::PrivateNamespaceMaxLen + sizeof("\\ProcessInitAPCMutex-pid=1234567890")];
	int mutexNamePos = SessionPrivateNamespace::MakeName(szMutexName, GetCurrentProcessId());
	swprintf_s(szMutexName + mutexNamePos, ARRAYSIZE(szMutexName) - mutexNamePos,
		L"\\ProcessInitAPCMutex-pid=%u", processId);

	return OpenMutex(desiredAccess, FALSE, szMutexName);
}
