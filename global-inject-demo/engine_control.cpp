#include "stdafx.h"
#include "engine_control.h"

namespace
{
	std::filesystem::path GetEnginePath()
	{
		// Use current architecture.
#ifdef _WIN64
		USHORT machine = IMAGE_FILE_MACHINE_AMD64;
#else // !_WIN64
		USHORT machine = IMAGE_FILE_MACHINE_I386;
#endif // _WIN64

		PCWSTR folderName;
		switch (machine) {
		case IMAGE_FILE_MACHINE_I386:
			folderName = L"32";
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			folderName = L"64";
			break;

		default:
			throw std::logic_error("Unknown architecture");
		}

		std::filesystem::path modulePath = wil::GetModuleFileName<std::wstring>();
		return modulePath.parent_path() / folderName;
	}
}

EngineControl::EngineControl()
{
	auto engineLibraryPath = GetEnginePath() / L"global-inject-lib.dll";

	engineModule.reset(LoadLibrary(engineLibraryPath.c_str()));
	THROW_LAST_ERROR_IF_NULL(engineModule);

	pGlobalHookSessionStart = reinterpret_cast<GLOBAL_HOOK_SESSION_START>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionStart"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionStart);

	pGlobalHookSessionHandleNewProcesses = reinterpret_cast<GLOBAL_HOOK_SESSION_HANDLE_NEW_PROCESSES>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionHandleNewProcesses"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionHandleNewProcesses);

	pGlobalHookSessionEnd = reinterpret_cast<GLOBAL_HOOK_SESSION_END>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionEnd"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionEnd);

	hGlobalHookSession = pGlobalHookSessionStart();
	if (!hGlobalHookSession) {
		throw std::runtime_error("Failed to start the global hooking session");
	}
}

EngineControl::~EngineControl()
{
	pGlobalHookSessionEnd(hGlobalHookSession);
}

int EngineControl::HandleNewProcesses()
{
	return pGlobalHookSessionHandleNewProcesses(hGlobalHookSession);
}
