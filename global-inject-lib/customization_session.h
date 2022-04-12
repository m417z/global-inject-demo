#pragma once

#include "new_process_injector.h"

class CustomizationSession {
public:
	CustomizationSession(const CustomizationSession&) = delete;
	CustomizationSession(CustomizationSession&&) = delete;
	CustomizationSession& operator=(const CustomizationSession&) = delete;
	CustomizationSession& operator=(CustomizationSession&&) = delete;

	static bool Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept;

private:
	CustomizationSession() = default;
	~CustomizationSession() = default;

	bool StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept;
	bool InitSession(bool skipThreadFreeze, HANDLE sessionManagerProcess) noexcept;
	void RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept;
	void Run() noexcept;
	void UninitSession() noexcept;

	wil::unique_process_handle m_sessionManagerProcess;
	wil::unique_mutex_nothrow m_sessionMutex;
	wil::unique_semaphore_nothrow m_sessionSemaphore;
	wil::semaphore_release_scope_exit m_sessionSemaphoreLock;
	std::optional<NewProcessInjector> m_newProcessInjector;
};
