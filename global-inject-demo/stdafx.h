#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

//////////////////////////////////////////////////////////////////////////
// STL

#include <filesystem>
#include <stdexcept>

//////////////////////////////////////////////////////////////////////////
// Libraries

#include <wil/stl.h> // must be included before other wil includes
#include <wil/resource.h>
#include <wil/result.h>
#include <wil/win32_helpers.h>
