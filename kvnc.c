#define UNICODE
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <initguid.h>
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>

#include <intrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _DEBUG
#  define Assert(cond) do { if (!(cond)) __debugbreak(); } while (0)
#  define HR(hr) Assert(SUCCEEDED(hr))
#else
#  define Assert(cond) (void)(cond)
#  define HR(hr) hr
#endif

#pragma comment (lib, "kernel32")
#pragma comment (lib, "user32")

void WinMainCRTStartup()
{
	ExitProcess(0);
}
