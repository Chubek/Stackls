#define WIN32_LEAN_AND_MEAN
#include <dbghelp.h>
#include <process.h>
#include <tlhelp32.h>
#include <errhandlingapi.h>
#include <strsafe.h>
#include <windows.h>
#include <tchar.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#if !defined(_WIN32) || !defined(_WIN64) || !defined(__windows__) || !defined(__WINDOWS__)
#warning "Compliant predefined CPP macros not detected."
#warning"This code is designed to be compiled and ran under the Microsoft Windows operating system."
#warning "A GNU Linux version is provided."
#endif

#ifdef __GNUC__
#define _inline_func static inline __attribute__ ((always_inline))
#define _fn_metadata file __FILE__, line __LINE__
#elif _MSC_VER
#define _inline_func static inline __forceinline
#define _fn_metadata file __FILE__, line __LINE__
#endif


#define _static_func static

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw (__VA_ARGS__)
#define STR_CRLF(...) STR (__VA_ARGS__ \r\n)


#ifndef HOST_MACHINE
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#endif

#ifndef PROCNAME_MAX
#define PROCNAME_MAX 128
#endif

#define MSG_FMT FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FORM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS

#define CTX_ProcessNameArr pSlsCtx->aProcessName
#define CTX_ProcessNameStr pSlsCtx->pszProcessName
#define CTX_ProcessHandle pSlsCtx->hProcess
#define CTX_Help32Snapshot pSlsCtx->hSnapshot
#define CTX_SelfHeapHandle pSlsCtx->hSelfHeap
#define CTX_ConsoleOutput pSlsCtx->hConsole

typedef struct {
	BYTE aProcessName[PROCNAME_MAX], *pszProcessName;
	HANDLE hProcess, hSnapshot, hSelfHeap, hConsole;
	PROCESS32ENTRY *pProcessEntry;
} STACKLSCTX, *PSTACKLSCTX;

_inline_func void
fnAllocateConsoleBuffer(PSTACKLSCTX pSlsCtx) {

}

_inline_func void
fnStacklsAllocateMemory(PSTACKLSCTX pSlsCtx) {
	pSlsCtx->
}

_inline_func void
fnStacklsInitProcEntry(PSTACKLSCTX pSlsCtx) {
	pSlsCtx->entryProcess->dwSize = sizeof(PROCESSENTRY32);
}

_inline_func void
fnStacklsI