#pragma once

//#define LOG(message, ...) ((void)0)

#define LOG(message, ...) \
	do \
	{ \
		WCHAR szBuffer[1025]; \
		wsprintf(szBuffer, L"[GLOBAL-INJECT-LOG] " message L"\n", __VA_ARGS__); \
		OutputDebugString(szBuffer); \
	} \
	while(0)
