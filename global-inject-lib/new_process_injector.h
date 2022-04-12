#pragma once

class NewProcessInjector {
public:
	NewProcessInjector(HANDLE hSessionManagerProcess);
	~NewProcessInjector();

	// Disable copying and moving to keep using the same
	// counter variable.
	NewProcessInjector(const NewProcessInjector&) = delete;
	NewProcessInjector(NewProcessInjector&&) noexcept = delete;
	NewProcessInjector& operator=(const NewProcessInjector&) = delete;
	NewProcessInjector& operator=(NewProcessInjector&&) noexcept = delete;

private:
	using CreateProcessInternalW_t = BOOL(WINAPI*)(
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
		DWORD_PTR unknown);

	static BOOL WINAPI CreateProcessInternalW_Hook(
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
		DWORD_PTR unknown);
	static void HandleCreatedProcess(LPPROCESS_INFORMATION lpProcessInformation);
	static HANDLE CreateProcessInitAPCMutex(HANDLE sessionManagerProcess, DWORD processId, BOOL initialOwner);

	static NewProcessInjector* volatile pThis; // limited to a single instance at a time

	HANDLE hSessionManagerProcess;
	CreateProcessInternalW_t originalCreateProcessInternalW = nullptr;
	volatile long nHookProcCallCounter = 0;
};
