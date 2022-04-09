# Global Injection and Hooking Demo

A simple global injection and hooking example. Injects into all processes and
hooks the `MessageBoxW` function. Also hooks the `CreateProcessInternalW`
function to be able to inject into newly created processes.

This simple implementation has several limitations. Refer to the blog post for
details: [Implementing Global Injection and Hooking in
Windows](https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/).

## Compiling

* Open the solution in Visual Studio.
* Go to Build -> Batch Build...
* Select the following three configurations, Configuration can be `Debug` or
  `Release`:
  * Project `global-inject-demo`, Platform `Win32`.
  * Project `global-inject-lib`, Platform `Win32`.
  * Project `global-inject-lib`, Platform `x64`.
* Click on Build.

## Running

* Make sure you have the following files in your execution folder:
  * `global-inject-demo.exe`
  * `global-inject-lib.dll`
  * `global-inject-lib_x64.dll`
* Run `global-inject-demo.exe` to load the library in all processes.
* Run `global-inject-demo.exe -u` to unload the library from all processes.

## Seeing it in action

Use any program that displays a message box using the `MessageBoxW` WinAPI
function. An easy option is running `slmgr.vbs` via the Run dialog (Win+R).
