#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <ntsecapi.h>
#include <sddl.h>
#include <tlhelp32.h>

// STL

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Libraries

#include <MinHook/MinHook.h>

#include <wil/stl.h> // must be included before other wil includes
#include <wil/resource.h>
#include <wil/result.h>
#include <wil/win32_helpers.h>

#include <wow64ext/wow64ext.h>
