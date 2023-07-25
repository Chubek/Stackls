#ifndef STACKLS_WINDOWS_H
#define STACKLS_WINDOWS_H

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

#define winerror_CHECK(CLOSURE, CALL)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        CLOSURE;                                                                                                       \
        INT64 dwLastError = GetLastError();                                                                            \
        if (dwLastError != 0)                                                                                          \
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

#define PROC_ENTRY_LEN sizeof(PROCESSENTRY32)
#define PROC_CONTEXT_LEN sizeof(CONTEXT)
#define STACKFRAME_LEN sizeof(dbgfn_StackFrameObj)
#define SYMINFO_LEN sizeof(dbgfn_SymbolInfoObj)
#define MAIN_CONTEXT_LEN sizeof(STACKLSCTX)
#define MESSAGE_LEN 1024

#define NO_FLAGS 0
#define MSG_FLAGS FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
#define NO_THREADS 0

#ifdef STACKLS_32BIT
#define dbgfn_StackWalk StackWalk
#define dbgfn_SymFunctionTableAccess SymFunctionTableAccess
#define dbgfn_SymGetModuleBase SymGetModuleBase
#define dbgfn_SymFromAddr SymGetSymFromAddr
#define dbgfn_SymbolInfoPtr PIMAGEHLP_SYMBOL
#define dbgfn_SymbolInfoObj IMAGEHLP_SYMBOL
#define dbgfn_SymbolLenIdent MaxNameLength
#define dbgfn_StackFrameObj STACKFRAME
#else
#define dbgfn_StackWalk StackWalk64
#define dbgfn_SymFunctionTableAccess SymFunctionTableAccess64
#define dbgfn_SymGetModuleBase SymGetModuleBase64
#define dbgfn_SymFromAddr SymGetSymFromAddr64
#define dbgfn_SymbolInfoPtr PIMAGEHLP_SYMBOL
#define dbgfn_SymbolInfoObj IMAGEHLP_SYMBOL
#define dbgfn_SymbolLenIdent MaxNameLength
#define dbgfn_StackFrameObj STACKFRAME64
#endif

#define CTX_MainContextPtr ppStraceCtx
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
#define CTX_OutputMode pStraceCtx->fOutputMode

typedef enum
{
    OutputToStdOut,
    OutputToFile,
} OutputMode;

typedef struct
{
    LPCTSTR pszProcessName, pszEntryProcesssName, pszLastSymName, pszStackIndicator, pszOutPath;
    OutputMode fOutputMode;
    HANDLE hProcess, hSnapshot, hOutput;
    DWORD64 qwDisplacement, qwStackCounter;
    PROCESSENTRY32 *pProcessEntry;
    LPSTACKFRAME pStackFrame;
    CONTEXT *pMachineContext;
    dbgfn_SymbolInfoPtr pCurrentSymbol;
    BOOL bTraceEnded;
} STACKLSCTX, *PSTACKLSCTX;

_noreturn_inline void fnErrorExit(PTCHAR pszMetadata, DWORD64 qwLastError);
_static_func void fnStacklsAllocateContextBuffer(PSTACKLSCTX *ppStraceCtx);
_static_func void fnStacklsAllocateStaticBuffers(PSTACKLSCTX pStraceCtx);
_coldbed_inline void fnStacklsOpenOutputFile(PSTACKLSCTX pStraceCtx);
_coldbed_inline void fnStacklsOpenSnapshotHandle(PSTACKLSCTX pStraceCtx);
_coldbed_inline void fnStacklsOpenProcessHandle(PSTACKLSCTX pStraceCtx);
_coldbed_inline void fnStacklsCloseAllHandles(PSTACKLSCTX pStraceCtx);
_hotbed_inline void fnStacklsFindProcessHandle(PSTACKLSCTX pStraceCtx);
_normal_inline void fnStacklsInitiateContextAndSymbols(PSTACKLSCTX pStraceCtx);
_normal_inline void fnStacklsRefreshSymbolContext(PSTACKLSCTX pStraceCtx);
_normal_inline void fnStacklsCleanUpSymbolContext(PSTACKLSCTX pStraceCtx);
_normal_inline void fnStacklsInitializeStackWalk(PSTACKLSCTX pStraceCtx);
_normal_inline void fnStacklsResetIndicatorStr(PSTACKLSCTX pStraceCtx);
_hotbed_inline void fnStacklsLoadTheNextFrame(PSTACKLSCTX pStraceCtx);
_hotbed_inline void fnStacklsExtractSymbolFromFrame(PSTACKLSCTX pStraceCtx);
_hotbed_inline void fnStacklsWriteSymbolToHandle(PSTACKLSCTX pStraceCtx);
_hotbed_inline void fnStacklsIterateAndWalkStack(PSTACKLSCTX pStraceCtx);
void fnDisplayHelp();
void fnParseCmdlineArgs(int nArgs, PTCHAR *szArglist, PSTACKLSCTX pStraceCtx);

#endif