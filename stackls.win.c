#define WIN32_LEAN_AND_MEAN
#include <dbghelp.h>
#include <errhandlingapi.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <windows.h>

#ifdef __GNUC__
#define _normal_inline static inline __attribute__((always_inline))
#define _hotbed_inline static inline __attribute__((always_inline, hot))
#define _coldbed_inline static inline __attribute__((always_inline, cold))
#define _noreturn_inline static inline __attribute__((noreturn, always_inline, hot))
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __PRETTY_FUNCTION__
#elif _MSC_VER
#define _normal_inline static inline __declspec(always_inline)
#define _hotbed_inline static inline __declspec(always_inline, hot)
#define _coldbed_inline static inline __declspec(always_inline, cold)
#define _noreturn_inline static inline __declspec(noreturn, always_inline, hot)
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __func__
#endif

#define _static_func static
#define _static_obj static

#if defined(_M_IX86) || defined(__x86__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_I386
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        STACKW->AddrPC.Offset = CONTEXT->Eip;                                                                          \
        STACKW->AddrPC.Mode = AddrModeFlat;                                                                            \
        STACKW->AddrFrame.Offset = CONTEXT->Ebp;                                                                       \
        STACKW->AddrFrame.Mode = AddrModeFlat;                                                                         \
        STACKW->AddrStack.Offset = CONTEXT->Esp;                                                                       \
        STACKW->AddrStack.Mode = AddrModeFlat;                                                                         \
    } while (0)
#elif defined(_M_IX64) || defined(_M_AMD64) || defined(__x86_64__) || defined(__amd64__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        STACKW->AddrPC.Offset = CONTEXT->Rip;                                                                          \
        STACKW->AddrPC.Mode = AddrModeFlat;                                                                            \
        STACKW->AddrFrame.Offset = CONTEXT->Rbp;                                                                       \
        STACKW->AddrFrame.Mode = AddrModeFlat;                                                                         \
        STACKW->AddrStack.Offset = CONTEXT->Rsp;                                                                       \
        STACKW->AddrStack.Mode = AddrModeFlat;                                                                         \
    } while (0)
#elif defined(_M_IA64) || defined(__ia64__)
#define MACHINE_TYPE IMAGE_FILE_MACHINE_IA64
#define ASSIGN_MACHINE_VALUES(STACKW, CONTEXT)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        STACKW->AddrPC.Offset = CONTEXT->StIIP;                                                                        \
        STACKW->AddrPC.Mode = AddrModeFlat;                                                                            \
        STACKW->AddrFrame.Offset = CONTEXT->IntSp;                                                                     \
        STACKW->AddrFrame.Mode = AddrModeFlat;                                                                         \
        STACKW->AddrStack.Offset = CONTEXT->IntSP;                                                                     \
        STACKW->AddrStack.Mode = AddrModeFlat;                                                                         \
        STACKW->AddrBStore.Offset = CONTEXT->RsBSP;                                                                    \
        STACKW->AddrBStore.Mode = AddrModeFlat;                                                                        \
    } while (0)
#endif

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw(__VA_ARGS__)
#define STR_CRLF(...) STR(__VA_ARGS__ \r\n)

#define winerror_CHECK(CLOSURE, CALL)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        CLOSURE;                                                                                                       \
        DWORD64 dwLastError = GetLastError();                                                                          \
        if (dwLastError < 0)                                                                                           \
            fnErrorExit(STR_CRLF(at call CALL, _fn_metadata), dwLastError);                                            \
    } while (0)

#ifndef MAX_PROC_NAME
#define MAX_PROC_NAME 128
#endif

#ifndef MAX_SYM_NAME
#define MAX_SYM_NAME ((2048 * sizeof(TCHAR)) + sizeof(SYMBOL_INFO))
#endif

#ifndef MAX_IND_SIZE
#define MAX_IND_SIZE 4096
#endif

#ifndef MAX_MDATA_SIZE
#define MAX_MDATA_SIZE 512
#endif

#define NO_FLAGS 0
#define MSG_FLAGS FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
#define NO_THREADS 0

#ifdef Stackls_32BIT
#define dbgfn_StackWalk StackWalk
#define dbgfn_SymFunctionTableAccess SymFunctionTableAccess
#define dbgfn_SymGetModuleBase SymGetModuleBase
#define dbgfn_SymFromAddr SymGetSymFromAddr
#define dbgfn_SymbolInfoPtr PIMAGEHLP_SYMBOL
#define dbgfn_SymbolInfoObj IMAGEHLP_SYMBOL
#define dbgfn_SymbolLenIdent MaxNameLength
#else
#define dbgfn_StackWalk StackWalk64
#define dbgfn_SymFunctionTableAccess SymFunctionTableAccess64
#define dbgfn_SymGetModuleBase SymGetModuleBase64
#define dbgfn_SymFromAddr SymFromAddr
#define dbgfn_SymbolInfoPtr PSYMBOL_INFO
#define dbgfn_SymbolInfoObj SYMBOL_INFO
#define dbgfn_SymbolLenIdent MaxNameLen
#endif

#define CTX_MainContextObj pStraceCtx
#define CTX_ProcessNameStr pStraceCtx->pszProcessName
#define CTX_LastSymNameStr pStraceCtx->pszLastSymName
#define CTX_IndicatorStr pStraceCtx->pszStackIndicator
#define CTX_OutputPathStr pStraceCtx->pszOutPath
#define CTX_OutputFileHandle pStraceCtx->hOutput
#define CTX_EntryProcessName pStraceCtx->pszEntryProcesssName
#define CTX_ProcessHandle pStraceCtx->hProcess
#define CTX_Help32SnapShot pStraceCtx->hSnapshot
#define CTX_ProcessEntryBuff pStraceCtx->pProcessEntry
#define CTX_CurrentStackFrame pStraceCtx->pStackFrame
#define CTX_MachineContext pStraceCtx->pMachineContext
#define CTX_StackIsAtBottom pStraceCtx->bTraceEnded
#define CTX_CurrentSymbol pStraceCtx->pCurrentSymbol
#define CTX_Displacement pStraceCtx->qwDisplacement
#define CTX_StackCounter pStraceCtx->qwStackCounter

typedef struct
{
    PTCHAR pszProcessName, pszEntryProcesssName, pszLastSymName, pszStackIndicator, pszOutPath;
    HANDLE hProcess, hSnapshot, hOutput;
    DWORD64 qwDisplacement, qwStackCounter;
    PROCESSENTRY32 *pProcessEntry;
    LPSTACKFRAME pStackFrame;
    CONTEXT *pMachineContext;
    dbgfn_SymbolInfoPtr pCurrentSymbol;
    BOOL bTraceEnded;
} STACKLSCTX, *PSTACKLSCTX;

_noreturn_inline void fnErrorExit(PTCHAR pszMetadata, DWORD64 qwLastError)
{
    SIZE_T sizeMetadata, sizeMessage;
    PTCHAR pszMessage;
    HANDLE hStdOut;

    sizeMessage =
        FormatMessage(MSG_FLAGS, NULL, qwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), pszMessage, 0, NULL);
    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    StringCbLength(pszMetadata, MAX_MDATA_SIZE, &sizeMetadata);

    WriteFile(hStdOut, pszMessage, sizeMessage, NULL, NULL);
    WriteFile(hStdOut, pszMetadata, sizeMetadata, NULL, NULL);
    ExitProcess(qwLastError);
}

_static_func void fnStacklsAllocateStaticBuffers(PSTACKLSCTX pStraceCtx)
{
    _static_obj STACKLSCTX objStacklsMain = {0};
    _static_obj PROCESSENTRY32 objProcessEntry = {0};
    _static_obj STACKFRAME64 objStackFrame = {0};
    _static_obj CONTEXT objMachineContext = {0};
    _static_obj dbgfn_SymbolInfoObj objSymbolInfo = {0};
    _static_obj TCHAR aProcessName[MAX_PROC_NAME] = {0};
    _static_obj TCHAR aLastSymName[MAX_SYM_NAME] = {0};
    _static_obj TCHAR aStackIndicator[MAX_IND_SIZE] = {0};
    _static_obj TCHAR aOutputPath[MAX_PATH] = {0};

    SecureZeroMemory(&objStacklsMain, sizeof(STACKLSCTX));

    CTX_MainContextObj = &objStacklsMain;
    CTX_ProcessEntryBuff = &objProcessEntry;
    CTX_CurrentStackFrame = &objStackFrame;
    CTX_MachineContext = &objMachineContext;
    CTX_CurrentSymbol = &objSymbolInfo;
    CTX_ProcessNameStr = &aProcessName[0];
    CTX_LastSymNameStr = &aLastSymName[0];
    CTX_IndicatorStr = &aStackIndicator[0];
    CTX_OutputPathStr = &aOutputPath[0];
}

_coldbed_inline void fnStacklsOpenOutputFile(PSTACKLSCTX pStraceCtx)
{
    if (!CTX_OutputPathStr)
    {
        winerror_CHECK(CTX_OutputFileHandle = GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle);
    }
    else
    {
        winerror_CHECK(CTX_OutputFileHandle = CreateFile(CTX_OutputPathStr, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                                         FILE_ATTRIBUTE_NORMAL, NULL),
                       CreateFile);
    }
}

_coldbed_inline void fnStacklsOpenSnapshotHandle(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CTX_Help32SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CreateToolhelp32Snapshot);
}

_coldbed_inline void fnStacklsOpenProcessHandle(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CTX_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CTX_ProcessEntryBuff->th32ProcessID),
                   OpenProcess);
}

_coldbed_inline void fnStacklsCloseAllHandles(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CloseHandle(CTX_OutputFileHandle), CloseHandle);
    winerror_CHECK(CloseHandle(CTX_Help32SnapShot), CloseHandle);
    winerror_CHECK(CloseHandle(CTX_ProcessHandle), CloseHandle);
}

_hotbed_inline void fnStacklsFindProcessHandle(PSTACKLSCTX pStraceCtx)
{
    int dwStrCmpRes;
    CTX_ProcessEntryBuff->dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(CTX_Help32SnapShot, CTX_ProcessEntryBuff))
    {
        while (Process32Next(CTX_Help32SnapShot, CTX_ProcessEntryBuff))
        {
            CTX_EntryProcessName = &CTX_ProcessEntryBuff->szExeFile[0];
            dwStrCmpRes = lstrcmpi(CTX_ProcessNameStr, CTX_EntryProcessName);
            if (!dwStrCmpRes)
            {
                fnStacklsOpenProcessHandle(pStraceCtx);
            }
        }
    }
}

_normal_inline void fnStacklsInitiateContextAndSymbols(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(RtlCaptureContext(CTX_MachineContext), RtlCaptureContext);
    winerror_CHECK(SymInitialize(CTX_ProcessHandle, NULL, TRUE), SymInitialize);
    CTX_CurrentSymbol->SizeOfStruct = sizeof(dbgfn_SymbolInfoObj);
    CTX_CurrentSymbol->dbgfn_SymbolLenIdent = MAX_SYM_NAME;
}

_normal_inline void fnStacklsInitializeStackWalk(PSTACKLSCTX pStraceCtx)
{
    SecureZeroMemory(CTX_CurrentStackFrame, sizeof(STACKFRAME64));
    ASSIGN_MACHINE_VALUES(CTX_CurrentStackFrame, CTX_MachineContext);
}

_normal_inline void fnStacklsResetIndicatorStr(PSTACKLSCTX pStraceCtx)
{
    SecureZeroMemory(CTX_IndicatorStr, MAX_IND_SIZE * sizeof(TCHAR));
}

_hotbed_inline void fnStacklsLoadTheNextFrame(PSTACKLSCTX pStraceCtx)
{
    CTX_StackIsAtBottom =
        !(dbgfn_StackWalk(MACHINE_TYPE, CTX_ProcessHandle, NO_THREADS, CTX_CurrentStackFrame, CTX_MachineContext, NULL,
                          dbgfn_SymFunctionTableAccess, dbgfn_SymGetModuleBase, NULL));
}

_hotbed_inline void fnStacklsExtractSymbolFromFrame(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(dbgfn_SymFromAddr(CTX_ProcessHandle, CTX_CurrentStackFrame->AddrPC.Offset, &CTX_Displacement,
                                     CTX_CurrentSymbol),
                   SymFromAddr);
    winerror_CHECK(
        UnDecorateSymbolName(CTX_CurrentSymbol->Name, (PSTR)CTX_LastSymNameStr, MAX_SYM_NAME, UNDNAME_COMPLETE),
        UnDecorateSymbolName);
}

_hotbed_inline void fnStacklsWriteSymbolToHandle(PSTACKLSCTX pStraceCtx)
{
    if (CTX_StackIsAtBottom)
        return;
    SIZE_T qwWritten, qwRead;
    fnStacklsResetIndicatorStr(pStraceCtx);
    winerror_CHECK(
        StringCchPrintf(CTX_IndicatorStr, MAX_IND_SIZE, TEXT("[%lu] %s\n"), CTX_StackCounter, CTX_LastSymNameStr),
        StringCchPrintf);
    winerror_CHECK(StringCbLength(CTX_IndicatorStr, MAX_IND_SIZE, &qwRead), StringCbLength);
    winerror_CHECK(WriteFile(CTX_OutputFileHandle, CTX_IndicatorStr, qwRead, (LPDWORD)&qwWritten, NULL), WriteFile);
}

_hotbed_inline void fnStacklsIterateAndWalkStack(PSTACKLSCTX pStraceCtx)
{
    fnStacklsOpenOutputFile(pStraceCtx);
    fnStacklsOpenSnapshotHandle(pStraceCtx);
    fnStacklsFindProcessHandle(pStraceCtx);
    fnStacklsInitiateContextAndSymbols(pStraceCtx);
    fnStacklsInitializeStackWalk(pStraceCtx);

    while (!CTX_StackIsAtBottom)
    {
        fnStacklsLoadTheNextFrame(pStraceCtx);
        fnStacklsExtractSymbolFromFrame(pStraceCtx);
        fnStacklsWriteSymbolToHandle(pStraceCtx);
    }

    fnStacklsCloseAllHandles(pStraceCtx);
}

void fnDisplayHelp()
{
    ExitProcess(0);
}

void fnParseCmdlineArgs(int nArgs, PTCHAR *szArglist, PSTACKLSCTX pStraceCtx)
{
    if (nArgs == 1)
        fnDisplayHelp();
    else if (nArgs == 2)
    {
        if (!lstrcmpi(szArglist[1], "--help") || !lstrcmpi(szArglist[1], "-h"))
            fnDisplayHelp();
        else
        {
            SIZE_T qwArglen;
            winerror_CHECK(StringCbLength(&szArglist[1][0], MAX_PROC_NAME, &qwArglen), StringCbLength);
            winerror_CHECK(StringCbCopy(CTX_ProcessNameStr, qwArglen, szArglist[1]), StringCbCopy);
            CTX_OutputPathStr = NULL;
        }
    }
    else if (nArgs == 4)
    {
        SIZE_T qwProcessNameLen, qwOutputPathLen;
        winerror_CHECK(StringCbLength(&szArglist[2][0], MAX_PATH, &qwOutputPathLen), StrinCbLength);
        winerror_CHECK(StringCbLength(&szArglist[3][0], MAX_PROC_NAME, &qwProcessNameLen), StrinCbLength);
        winerror_CHECK(StringCbCopy(CTX_OutputPathStr, qwOutputPathLen, szArglist[2]), StringCbCopy);
        winerror_CHECK(StringCbCopy(CTX_ProcessNameStr, qwProcessNameLen, szArglist[3]), StringCbCopy);
    }
    else
    {
        fnDisplayHelp();
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPCTSTR lpCmdLine, int nCmdShow)
{
    int nArgs;
    PTCHAR *szArglist;
    PSTACKLSCTX pStraceCtx;

    winerror_CHECK(szArglist = (PTCHAR *)CommandLineToArgvW((LPWSTR)lpCmdLine, &nArgs), CommandLineToArgvW);

    fnStacklsAllocateStaticBuffers(pStraceCtx);
    fnParseCmdlineArgs(nArgs, szArglist, pStraceCtx);
    fnStacklsIterateAndWalkStack(pStraceCtx);
}