#define WIN32_LEAN_AND_MEAN
#include <dbghelp.h>
#include <process.h>
#include <tlhelp32.h>
#include <heapapi.h>
#include <handleapi.h>
#include <stringapiset.h>
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

#define yield_CHECK(CLOSURE, MSG)								\
	do {														\
		if (!((BOOL)(CLOSURE)))									\
			fnErrorExit(STR_CRLF(calling MSG, _fn_metadata));	\
	} while (0)

#ifndef HOST_MACHINE
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#endif

#ifndef PROCNAME_MAX
#define PROCNAME_MAX 128
#endif

#define CTX_ProcessNameArr pSlsCtx->aProcessName
#define CTX_ProcessNameStr pSlsCtx->pszProcessName
#define CTX_EntryProcessName pSlsCtx->pszEntryProcesssName
#define CTX_ProcessHandle pSlsCtx->hProcess
#define CTX_Help32SnapShot pSlsCtx->hSnapshot
#define CTX_SelfHeapHandle pSlsCtx->hSelfHeap
#define CTX_StandardInput pSlsCtx->hStdIn
#define CTX_StandardOutput pSlsCtx->hStdOut
#define CTX_StandardError pSlsCtx->hStdErr
#define CTX_Process32Entry pSlsCtx->pProcessEntry


typedef struct {
	BYTE aProcessName[PROCNAME_MAX], *pszProcessName, *pszEntryProcesssName;
	HANDLE hProcess, hSnapshot, hSelfHeap, hStdin, hStdOut, hStdErr;
	PROCESS32ENTRY *pProcessEntry;
} STACKLSCTX, *PSTACKLSCTX;

void 
fnErrorExit(LPTSTR lpszFunction) 
{ 
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw); 
}

_inline_func void
fnStacklsInitHandles(PSTACKLSCTX pSlsCtx) {
	CTX_ProcessNameStr = &CTX_ProcessNameArr[0];
	yield_CHECK(CTX_SelfHeapHandle = GetProcessHeap(), GetProcessHeap);
	yield_CHECK(CTX_StandardInput = GetStdHandle(STD_INPUT_HANDLE), GetStdHandle);
	yield_CHECK(CTX_StandardOutput = GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle);
	yield_CHECK(CTX_StandardError = GetStdHandle(STD_ERROR_HANDLE), GetStdHandle);
	yield_CHECK(CTX_Help32SnapShot = CreateToolhelp32Snapshot(T32Cs_SNAPPROCESS, 0), CreateToolhelp32Snapshot);
}

_inline_func void
fnStacklsAllocateProcEntry(PSTACKLSCTX pSlsCtx) {
	yield_CHECK(CTX_Process32Entry = (PROCESS32ENTRY*)HeapAlloc(CTX_SelfHeapHandle, HEAP_ZERO_MEMORY, sizeof(PROCESS32ENTRY)), HeapAlloc);
}

_inline_func void
fnStacklsDeallocateProcEntry(PSTACKLSCTX pSlsCtx) {
	yield_CHECK(HeapFree(CTX_SelfHeapHandle, 0, CTX_Process32Entry), HeapFree);
	yield_CHECK(CloseHandle(CTX_SelfHeapHandle), CloseHandle);
}

_inline_func void
fnStacklsFindProcessHandle(PSTACKLSCTX pSlsCtx) {
	int dwStrCmpRes;
	CTX_Process32Entry->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(CTX_Help32SnapShot, CTX_Process32Entry)) {
		while (Process32Next(CTX_Help32SnapShot, CTX_Process32Entry)) {
			CTX_EntryProcessName = &CTX_Process32Entry->szExecFile[0];
			yield_CHECK(dwStrCmpRes = StringCompareEx(LOCAL_NAME_INVARIANT, 0, CTX_ProcessNameStr, -1, CTX_EntryProcessName, -1, NULL, NULL, 0), StringCompareEx);
			if (!dwStrCmpRes) {
				yield_CHECK(CTX_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CTX_Process32Entry->th32ProcessID), OpenProcess);
				
			}
		}
	}
}

_inline_func void
fnStacklsI