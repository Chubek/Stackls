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
#define _normal_inline static inline __attribute__ ((always_inline))
#define _hotbed_inline static inline __attribute__ ((always_inline, hot))
#define _coldbed_func static inline __attribute__ ((always_inline, cold))
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __PRETTY_FUNCTION__
#elif _MSC_VER
#define _normal_inline static inline __declspec(always_inline)
#define _hotbed_inline static inline __declspec(always_inline, hot)
#define _coldbed_func static inline __declspec(always_inline, cold)
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __func__
#endif

#define _static_func static


#if defined(_M_IX86) || defined(__x86__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_I386
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)			\
	do {												\
		STACKW->AddrPC.Offset = CONTEXT.Eip;			\
		STACKW->AddrPC.Mode = AddrModeFlat;				\
		STACKW->AddrFrame.Offset = CONTEXT.Ebp;			\
		STACKW->AddrFrame.Mode = AddrModeFlat;			\
		STACKW->AddrStack.Offset = CONTEXT.Esp;			\
		STACKW->AddrStack.Mode = AddrModeFlat;			\
	} while (0)
#elif defined(_M_IX64) || defined(_M_AMD64) || defined(__x86_64__) || defined(__amd64__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_IA64
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)			\
	do {												\
		STACKW->AddrPC.Offset = CONTEXT.Rip;			\
		STACKW->AddrPC.Mode = AddrModeFlat;				\
		STACKW->AddrFrame.Offset = CONTEXT.Rbp;			\
		STACKW->AddrFrame.Mode = AddrModeFlat;			\
		STACKW->AddrStack.Offset = CONTEXT.Rsp;			\
		STACKW->AddrStack.Mode = AddrModeFlat;			\
	} while (0)
#elif defined(_M_IA64) || defined(__ia64__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)			\
	do {												\
		STACKW->AddrPC.Offset = CONTEXT.StIIP;			\
		STACKW->AddrPC.Mode = AddrModeFlat;				\
		STACKW->AddrFrame.Offset = CONTEXT.IntSp;		\
		STACKW->AddrFrame.Mode = AddrModeFlat;			\
		STACKW->AddrStack.Offset = CONTEXT.IntSP;		\
		STACKW->AddrStack.Mode = AddrModeFlat;			\
		STACKW->AddrBStore.Offset = CONTEXT.RsBSP;		\
		STACKW->AddrBStore.Mode = AddrModeFlat;			\
	} while (0)
#endif

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw (__VA_ARGS__)
#define STR_CRLF(...) STR (__VA_ARGS__ \r\n)

#define winerror_CHECK(CLOSURE, MSG)								\
	do {														\
		if (!((BOOL)(CLOSURE)))									\
			fnErrorExit(STR_CRLF(calling MSG, _fn_metadata));	\
	} while (0)

#ifndef MAX_PROC_NAME
#define MAX_PROC_NAME 128
#endif

#ifndef MAX_SYM_NAME
#define MAX_SYM_NAME ((2048 * sizeof(TCHAR)) + sizeof(SYMBOL_INFO))
#endif	

#define NO_FLAGS 0
#define NO_THREADS 0

#define CTX_ProcessNameArr pSlsCtx->aProcessName
#define CTX_ProcessNameStr pSlsCtx->pszProcessName
#define CTX_EntryProcessName pSlsCtx->pszEntryProcesssName
#define CTX_ProcessHandle pSlsCtx->hProcess
#define CTX_Help32SnapShot pSlsCtx->hSnapshot
#define CTX_SelfHeapHandle pSlsCtx->hSelfHeap
#define CTX_StandardInput pSlsCtx->hStdIn
#define CTX_StandardOutput pSlsCtx->hStdOut
#define CTX_StandardError pSlsCtx->hStdErr
#define CTX_ProcessEntryBuff pSlsCtx->pProcessEntry
#define CTX_CurrentStackFrame pSlsCtx->pStackFrame
#define CTX_MachineContext pSlsCtx->pMachineContext
#define CTX_StackIsAtBottom pSlsCtx->bTraceEnded
#define CTX_CurrentSymbol pSlsCtx->pCurrentSymbol

typedef struct {
	BYTE aProcessName[MAX_PROC_NAME], *pszProcessName, *pszEntryProcesssName;
	HANDLE hProcess, hSnapshot, hSelfHeap, hStdin, hStdOut, hStdErr;
	PROCESS32ENTRY *pProcessEntry;
	LPSTACKFRAME pStackFrame;
	CONTEXT *pMachineContext;
	PSYMBOL_INFO pCurrentSymbol;
	BOOL bTraceEnded;
} STACKLSCTX, *PSTACKLSCTX;

_hotbed_inline void 
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

_coldbed_inline void
fnStacklsInitHandles(PSTACKLSCTX pSlsCtx) {
	CTX_ProcessNameStr = &CTX_ProcessNameArr[0];
	winerror_CHECK(CTX_StandardInput = GetStdHandle(STD_INPUT_HANDLE), GetStdHandle);
	winerror_CHECK(CTX_StandardOutput = GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle);
	winerror_CHECK(CTX_StandardError = GetStdHandle(STD_ERROR_HANDLE), GetStdHandle);
	winerror_CHECK(CTX_SelfHeapHandle = GetProcessHeap(), GetProcessHeap);
	winerror_CHECK(CTX_Help32SnapShot = CreateToolhelp32Snapshot(T32Cs_SNAPPROCESS, 0), CreateToolhelp32Snapshot);
}

_coldbed_inline void
fnStacklsCloseHandles(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(CloseHandle(CTX_SelfHeapHandle), CloseHandle);
	winerror_CHECK(CloseHandle(CTX_Help32SnapShor), CloseHandle);
	winerror_CHECK(CloseHandle(CTX_StandardInput), CloseHandle);
	winerror_CHECK(CloseHandle(CTX_StandardOutput), CloseHandle);
	winerror_CHECK(CloseHandle(CTX_StandardError), CloseHandle);
}

_coldbed_inline void
fnStacklsAllocateProcEntryBuffer(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(CTX_ProcessEntryBuff = (PROCESS32ENTRY*)HeapAlloc(CTX_SelfHeapHandle, HEAP_ZERO_MEMORY, sizeof(PROCESS32ENTRY)), HeapAlloc);
}

_coldbed_inline void
fnStacklsDeallocateProcEntryBuffer(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(HeapFree(CTX_SelfHeapHandle, NO_FLAGS, CTX_ProcessEntryBuff), HeapFree);
}

_coldbed_inline void
fnStacklsAllocateStackFrameBuffer(PSTACKLSCTX pSlscCtx) {
	winerror_CHECK(CTX_CurrentStackFrame = (LPSTACKFRAME)HeapAlloc(CTX_SelfHeapHandle, HEAP_ZERO_MEMORY, sizeof(*LPSTACKFRAME)), HeapAlloc);
}

_coldbed_inline void
fnStacklsDeallocateStackFrameBuffer(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(HeapFree(CTX_SelfHeapHandle, NO_FLAGS, CTX_CurrentStackFrame), HeapFree);
}

_coldbed_inline void
fnStacklsAllocateMachineContextBuffer(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(CTX_MachineContext = (CONTEXT*)HeapAlloc(CTX_SelfHeapHandle, HEAP_ZERO_MEMORY, sizeof(CONTEXT)), HeapAlloc);
}

_coldbed_inline void
fnStacklsDeallocateMachineContextBuffer(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(HeapFree(CTX_SelfHeapHandle, NO_FLAGS, CTX_MachineContext), HeapFree);
}

_coldbed_inline void
fnStacklsAllocateCurrentSymbolBuffer(PSTACKLS pSlsCtx) {
	winerror_CHECK(CTX_CurrentSymbol = (PSYMBOL_INFO)HeapAlloc(CTX_SelfHeapHandle, HEAP_ZERO, MAX_SYM_NAME), HeapAlloc);
}

_coldbed_inline void
fnStacklsDeallocateCurrentSymbolBuffer(PSTACKLS pSlsCtx) {
	winerror_CHECK(HeapFree(CTX_SelfHeapHandle, NO_FLAGS, CTX_CurrentSymbol), HeapFree);
}

_normal_inline void
fnStacklsOpenProcessHandle(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(CTX_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CTX_ProcessEntryBuff->th32ProcessID), OpenProcess);
}

_normal_inline void
fnStacklsInitiateContextAndSymbols(PSTACKLSCTX pSlsCtx) {
	winerror_CHECK(RtlCaptureContext(CTX_MachineContext), RtlCaptureContext);
	winerror_CHECK(SymInitialize(CTX_ProcessHandle, NULL, TRUE), SymInitialize);
	CTX_CurrentSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	CTX_CurrentSymbol->MaxNameLength = MAX_SYM_NAME;
}

_normal_inline void
fnStacklsInitializeStackWalk(PSTACKLSCTX pSlsCtx) {
	SecureZeroMemory(CTX_CurrentStackFrame, sizeof(STACKFRAME64));
	ASSIGN_MACHINE_VALUES(CTX_CurrentStackFrame, CTX_MachineContext);
}

_hotbed_inline void
fnStacklsFindProcessHandle(PSTACKLSCTX pSlsCtx) {
	int dwStrCmpRes;
	CTX_ProcessEntryBuff->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(CTX_Help32SnapShot, CTX_ProcessEntryBuff)) {
		while (Process32Next(CTX_Help32SnapShot, CTX_ProcessEntryBuff)) {
			CTX_EntryProcessName = &CTX_ProcessEntryBuff->szExecFile[0];
			winerror_CHECK(dwStrCmpRes = StringCompareEx(LOCAL_NAME_INVARIANT, NO_FLAGS, CTX_ProcessNameStr, -1, CTX_EntryProcessName, -1, NULL, NULL, NO_FLAGS), StringCompareEx);
			if (!dwStrCmpRes) {
				fnStacklsOpenProcessHandle(pSlsCtx);
				fnStacklsDeallocateProcEntryBuffer(pSlsCtx);
			}
		}
	}
}

_hotbed_inline void 
fnStacklsLoadTheNextFrame(PSTACKLSCTX pSlsCtx) {
	CTX_StackIsAtBottom = !(StackWalk64(MACHINE_TYPE, CTX_ProcessHandle, NO_THREADS, CTX_CurrentStackFrame, CTX_MachineContext, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL));
}