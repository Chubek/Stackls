#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <dbghelp.h>
#include <errhandlingapi.h>

#include "stackls.com.h"
#include "stackls.win.h"

void fnErrorExit(PTCHAR pszMetadata, DWORD64 qwLastError)
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

void fnStacklsAllocateContextBuffer(PSTACKLSCTX *ppStraceCtx)
{
    BYTE objStacklsMainBuffer[sizeof(STACKLSCTX)] = {0};
    *CTX_MainContextPtr = (PSTACKLSCTX)&objStacklsMainBuffer[0];
}

void fnStacklsAllocateStaticBuffers(PSTACKLSCTX pStraceCtx)
{
    BYTE objProcessEntry[sizeof(PROCESSENTRY32)] = {0};
    BYTE objMachineContext[sizeof(CONTEXT)] = {0};
    BYTE objStackFrame[sizeof(dbgfn_StackFrameObj)] = {0};
    BYTE objSymbolInfo[sizeof(dbgfn_SymbolInfoObj)] = {0};
    TCHAR aProcessName[MAX_PROC_NAME] = {0};
    TCHAR aLastSymName[MAX_SYM_NAME] = {0};
    TCHAR aStackIndicator[MAX_IND_SIZE] = {0};
    TCHAR aOutputPath[MAX_PATH] = {0};

    CTX_ProcessEntryBuff = (PROCESSENTRY32*)&objProcessEntry[0];
    CTX_CurrentStackFrame = (dbgfn_StackFrameObj*)&objStackFrame[0];
    CTX_MachineContext = (CONTEXT*)&objMachineContext[0];
    CTX_CurrentSymbol = (dbgfn_SymbolInfoObj*)&objSymbolInfo[0];
    CTX_ProcessNameStr = (LPCTSTR)&aProcessName[0];
    CTX_LastSymNameStr = (LPCTSTR)&aLastSymName[0];
    CTX_IndicatorStr = (LPCTSTR)&aStackIndicator[0];
    CTX_OutputPathStr = (LPCTSTR)&aOutputPath[0];
}

void fnStacklsOpenOutputFile(PSTACKLSCTX pStraceCtx)
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
                   SymFromAddr);
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
        fnStacklsExtractSymbolFromFrame(pStraceCtx);
        fnStacklsWriteSymbolToHandle(pStraceCtx);
    }

    fnStacklsCloseAllHandles(pStraceCtx);
}

void fnDisplayHelp()
{
    ExitProcess(0);
}

void fnParseCmdlineArgs(int nArgs, PTCHAR* szArglist, PSTACKLSCTX pStraceCtx)
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

int _tmain(int nArgs, TCHAR *pszArglist[])
{
    PSTACKLSCTX pStraceCtx = {0};

    fnStacklsAllocateContextBuffer(&pStraceCtx);
    fnStacklsAllocateStaticBuffers(pStraceCtx);
    fnParseCmdlineArgs(nArgs, pszArglist, pStraceCtx);
    fnStacklsIterateAndWalkStack(pStraceCtx);
}  