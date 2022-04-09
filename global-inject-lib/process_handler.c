#include <windows.h>
#include "process_handler.h"
#include "MinHook/MinHook.h"

#define CREATE_FUNCTION_HOOK(func_name) \
	MH_CreateHook(func_name, func_name##_Hook, (void **)&Original##func_name)

#define DEFINE_HOOK_FUNCTION(func_name, ret_type, calling_conv, ...) \
	typedef ret_type(calling_conv *func_name##_type)(__VA_ARGS__); \
	static func_name##_type Original##func_name; \
	\
	static ret_type calling_conv func_name##_Hook(__VA_ARGS__) \
	{ \
		InterlockedIncrement(&nHookProcCallCounter); \
		\
		__try \
		{

#define END_HOOK_FUNCTION() \
		} \
		__finally \
		{ \
			InterlockedDecrement(&nHookProcCallCounter); \
		} \
	}

static volatile long nHookProcCallCounter = 0;

DEFINE_HOOK_FUNCTION(MessageBoxW, int, WINAPI, HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	static int counter = 0;
	counter++;

	WCHAR newText[1025];
	wsprintf(newText, L"Global injection and hooking demo!\n\n%s", lpText);

	WCHAR newTitle[1025];
	wsprintf(newTitle, L"[%d] %s", counter, lpCaption);

	return OriginalMessageBoxW(hWnd, newText, newTitle, uType);
}
END_HOOK_FUNCTION()

BOOL SetupProcessHandler(void)
{
	CREATE_FUNCTION_HOOK(MessageBoxW);

	return TRUE;
}

void DestroyProcessHandler(void)
{
	while(nHookProcCallCounter > 0)
		Sleep(10);
}
