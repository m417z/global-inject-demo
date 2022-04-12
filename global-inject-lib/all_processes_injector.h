#pragma once

class AllProcessesInjector {
public:
	AllProcessesInjector();

	int InjectIntoNewProcesses() noexcept;

private:
	void InjectIntoNewProcess(HANDLE hProcess, DWORD dwProcessId);
	static HANDLE CreateProcessInitAPCMutex(DWORD processId, BOOL initialOwner);
	static HANDLE OpenProcessInitAPCMutex(DWORD processId, DWORD desiredAccess);

	using NtGetNextProcess_t = NTSTATUS(NTAPI*)(
		_In_opt_ HANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Flags,
		_Out_ PHANDLE NewProcessHandle
		);

	using NtGetNextThread_t = NTSTATUS(NTAPI*)(
		_In_ HANDLE ProcessHandle,
		_In_opt_ HANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Flags,
		_Out_ PHANDLE NewThreadHandle
		);

	NtGetNextProcess_t NtGetNextProcess;
	NtGetNextThread_t NtGetNextThread;
	DWORD64 pRtlUserThreadStart;
	wil::unique_private_namespace_destroy appPrivateNamespace;
	wil::unique_process_handle lastEnumeratedProcess;
};
