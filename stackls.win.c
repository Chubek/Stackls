#define WIN32_LEAN_AND_MEAN
#define DBGHELP_TRANSLATE_TCHAR
#include <dbghelp.h>
#include <errhandlingapi.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <windows.h>

#include "stackls.com.h"
#include "stackls.win.h"

void fnErrorExit(PTCHAR pszMetadata, DWORD64 qwLastError)
{
    SIZE_T sizeMetadata, sizeMessage;
    LPCTSTR nullBufferMessage = NULL;
    HANDLE hStdOut;

    sizeMessage = FormatMessage(MSG_FLAGS, NULL, qwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                (LPSTR)&nullBufferMessage, 0, NULL);
    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    StringCbLength(pszMetadata, MAX_MDATA_SIZE, &sizeMetadata);

    WriteFile(hStdOut, nullBufferMessage, sizeMessage, NULL, NULL);
    WriteFile(hStdOut, pszMetadata, sizeMetadata, NULL, NULL);

    LocalFree(nullBufferMessage);

    ExitProcess(qwLastError);
}

void fnStacklsAllocateContextBuffer(PSTACKLSCTX *ppStraceCtx)
{
    _static_obj BYTE rawBufferMainContext[MAIN_CONTEXT_LEN] = {0};
    *CTX_MainContextPtr = (PSTACKLSCTX)&rawBufferMainContext[0];
}

void fnStacklsAllocateStaticBuffers(PSTACKLSCTX pStraceCtx)
{
    _static_obj BYTE rawBufferProcessEntry[PROC_ENTRY_LEN] = {0};
    _static_obj BYTE rawBufferMachineContext[PROC_CONTEXT_LEN] = {0};
    _static_obj BYTE rawBufferStackFrame[STACKFRAME_LEN] = {0};
    _static_obj BYTE rawBufferSymbolInfo[SYMINFO_LEN] = {0};
    _static_obj TCHAR rawBufferProccessName[MAX_PROC_NAME] = {0};
    _static_obj TCHAR rawBufferLastSymName[MAX_SYM_NAME] = {0};
    _static_obj TCHAR rawBufferStackIndicator[MAX_IND_SIZE] = {0};
    _static_obj TCHAR rawBufferOutputPath[MAX_PATH] = {0};

    CTX_ProcessEntryBuff = (PROCESSENTRY32 *)&rawBufferProcessEntry[0];
    CTX_CurrentStackFrame = (dbgfn_StackFrameObj *)&rawBufferStackFrame[0];
    CTX_MachineContext = (CONTEXT *)&rawBufferMachineContext[0];
    CTX_CurrentSymbol = (dbgfn_SymbolInfoObj *)&rawBufferSymbolInfo[0];
    CTX_ProcessNameStr = (LPCTSTR)&rawBufferProccessName[0];
    CTX_LastSymNameStr = (LPCTSTR)&rawBufferLastSymName[0];
    CTX_IndicatorStr = (LPCTSTR)&rawBufferStackIndicator[0];
    CTX_OutputPathStr = (LPCTSTR)&rawBufferOutputPath[0];
}

void fnStacklsOpenOutputFile(PSTACKLSCTX pStraceCtx)
{
    if (CTX_OutputMode == OutputToStdOut)
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

void fnStacklsOpenSnapshotHandle(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CTX_Help32SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CreateToolhelp32Snapshot);
}

void fnStacklsOpenProcessHandle(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CTX_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CTX_ProcessEntryBuff->th32ProcessID),
                   OpenProcess);
}

void fnStacklsCloseAllHandles(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(CloseHandle(CTX_OutputFileHandle), CloseHandle);
    winerror_CHECK(CloseHandle(CTX_Help32SnapShot), CloseHandle);
    winerror_CHECK(CloseHandle(CTX_ProcessHandle), CloseHandle);
}

void fnStacklsFindProcessHandle(PSTACKLSCTX pStraceCtx)
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
                return;
            }
        }
    }
}

void fnStacklsInitiateContextAndSymbols(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(RtlCaptureContext(CTX_MachineContext), RtlCaptureContext);
    winerror_CHECK(SymInitialize(CTX_ProcessHandle, NULL, TRUE), SymInitialize);
    CTX_CurrentSymbol->SizeOfStruct = sizeof(dbgfn_SymbolInfoObj);
    CTX_CurrentSymbol->dbgfn_SymbolLenIdent = MAX_SYM_NAME;
}

void fnStacklsRefreshSymbolContext(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(SymRefreshModuleList(CTX_ProcessHandle), SymRefreshModuleList);
}

void fnStacklsCleanUpSymbolContext(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(SymCleanup(CTX_ProcessHandle), SymCleanup);
}

void fnStacklsInitializeStackWalk(PSTACKLSCTX pStraceCtx)
{
    SecureZeroMemory(CTX_CurrentStackFrame, sizeof(STACKFRAME64));
    ASSIGN_MACHINE_VALUES(CTX_CurrentStackFrame, CTX_MachineContext);
}

void fnStacklsResetIndicatorStr(PSTACKLSCTX pStraceCtx)
{
    SecureZeroMemory(CTX_IndicatorStr, MAX_IND_SIZE * sizeof(TCHAR));
}

void fnStacklsLoadTheNextFrame(PSTACKLSCTX pStraceCtx)
{
    CTX_StackIsAtBottom =
        !(dbgfn_StackWalk(MACHINE_TYPE, CTX_ProcessHandle, NO_THREADS, CTX_CurrentStackFrame, CTX_MachineContext, NULL,
                          dbgfn_SymFunctionTableAccess, dbgfn_SymGetModuleBase, NULL));
}

void fnStacklsExtractSymbolFromFrame(PSTACKLSCTX pStraceCtx)
{
    winerror_CHECK(dbgfn_SymFromAddr(CTX_ProcessHandle, CTX_CurrentStackFrame->AddrPC.Offset, &CTX_Displacement,
                                     CTX_CurrentSymbol),
                   dbgfn_SymFromAddr);
    winerror_CHECK(
        UnDecorateSymbolName(CTX_CurrentSymbol->Name, (PSTR)CTX_LastSymNameStr, MAX_SYM_NAME, UNDNAME_COMPLETE),
        UnDecorateSymbolName);
}

void fnStacklsWriteSymbolToHandle(PSTACKLSCTX pStraceCtx)
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

void fnStacklsIterateAndWalkStack(PSTACKLSCTX pStraceCtx)
{
    fnStacklsOpenOutputFile(pStraceCtx);
    fnStacklsOpenSnapshotHandle(pStraceCtx);
    fnStacklsFindProcessHandle(pStraceCtx);
    fnStacklsInitiateContextAndSymbols(pStraceCtx);
    fnStacklsInitializeStackWalk(pStraceCtx);

    while (!CTX_StackIsAtBottom)
    {
        fnStacklsLoadTheNextFrame(pStraceCtx);
        fnStacklsRefreshSymbolContext(pStraceCtx);
        fnStacklsExtractSymbolFromFrame(pStraceCtx);
        fnStacklsWriteSymbolToHandle(pStraceCtx);
    }

    fnStacklsCleanUpSymbolContext(pStraceCtx);
    fnStacklsCloseAllHandles(pStraceCtx);
}

void fnDisplayHelp()
{
    ExitProcess(0);
}

void fnParseCmdlineArgs(int nArgs, TCHAR *szArglist[], PSTACKLSCTX pStraceCtx)
{
    if (nArgs == 1)
        fnDisplayHelp();
    else if (nArgs == 2)
    {
        if (!lstrcmpi(szArglist[1], "--help") || !lstrcmpi(szArglist[1], "-h"))
            fnDisplayHelp();
        else
        {
            winerror_CHECK(StringCbCopy(CTX_ProcessNameStr, MAX_PROC_NAME, szArglist[1]), StringCbCopy);
            CTX_OutputMode = OutputToStdOut;
        }
    }
    else if (nArgs == 4)
    {
        if (!lstrcmpi(szArglist[1], "-o"))
            fnDisplayHelp();
        else
        {
            winerror_CHECK(StringCbCopy(CTX_OutputPathStr, MAX_PATH, szArglist[2]), StringCbCopy);
            winerror_CHECK(StringCbCopy(CTX_ProcessNameStr, MAX_PROC_NAME, szArglist[3]), StringCbCopy);
            CTX_OutputMode = OutputToFile;
        }
    }
    else
    {
        fnDisplayHelp();
    }
}

int _tmain(int argc, TCHAR *argv[])
{
    PSTACKLSCTX pStraceCtx = 0;

    fnStacklsAllocateContextBuffer(&pStraceCtx);
    fnStacklsAllocateStaticBuffers(pStraceCtx);
    fnParseCmdlineArgs(argc, argv, pStraceCtx);
    fnStacklsIterateAndWalkStack(pStraceCtx);
}