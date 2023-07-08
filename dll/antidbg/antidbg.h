#pragma once
#include <cinttypes>
#include <Windows.h>
#include <Winternl.h>
#include <stdio.h>
#include <Tlhelp32.h>
// Error Codes
enum DBG_CATCH
{
	DBG_NONE = 0x0000,

	// Memory Codes (0x1000 range)
	DBG_BEINGEBUGGEDPEB = 0x1000,
	DBG_CHECKREMOTEDEBUGGERPRESENT = 0x1001,
	DBG_ISDEBUGGERPRESENT = 0x1002,
	DBG_NTGLOBALFLAGPEB = 0x1003,
	DBG_NTQUERYINFORMATIONPROCESS = 0x1004,
	DBG_FINDWINDOW = 0x1005,
	DBG_OUTPUTDEBUGSTRING = 0x1006,
	DBG_NTSETINFORMATIONTHREAD = 0x1007,
	DBG_DEBUGACTIVEPROCESS = 0x1008,
	DBG_PROCESSFILENAME = 0x1009,

	// CPU Codes (0x2000 range)
	DBG_HARDWAREDEBUGREGISTERS = 0x2000,
	DBG_MOVSS = 0x2001,

	// Timing Codes (0x3000 range)
	DBG_RDTSC = 0x3000,
	DBG_QUERYPERFORMANCECOUNTER = 0x3001,
	DBG_GETTICKCOUNT = 0x3002,

	// Exception Codes (0x4000 range)
	DBG_CLOSEHANDLEEXCEPTION = 0x4000,
	DBG_SINGLESTEPEXCEPTION = 0x4001,
	DBG_INT3CC = 0x4002,
	DBG_PREFIXHOP = 0x4003,
};

// Debugging messages
void DBG_MSG(WORD dbg_code, char* message);

// Dynamically resolved functions
typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

typedef struct timeKeeper {
	uint64_t timeUpperA;
	uint64_t timeLowerA;
	uint64_t timeUpperB;
	uint64_t timeLowerB;
} TimeKeeper;


#ifdef _WIN64
extern "C"
{
	int adbg_BeingDebuggedPEBx64();
	int adbg_NtGlobalFlagPEBx64();
	void adbg_GetTickCountx64();
	void adbg_QueryPerformanceCounterx64();
	void adbg_RDTSCx64(TimeKeeper*);
	void adbg_Int2Dx64();
	void adbg_Int3x64();
	void adbg_SingleStepExceptionx64();
};
#endif

// Memory
bool adbg_BeingDebuggedPEB();
bool adbg_CheckRemoteDebuggerPresent();
bool adbg_CheckWindowClassName();
bool adbg_CheckWindowName();
bool adbg_ProcessFileName();
bool adbg_IsDebuggerPresent();
bool adbg_NtGlobalFlagPEB();
bool adbg_NtQueryInformationProcess();
bool adbg_NtSetInformationThread();
bool adbg_DebugActiveProcess(const char*);

// CPU
bool adbg_HardwareDebugRegisters();
bool adbg_MovSS();

// Timing
bool adbg_RDTSC();
bool adbg_QueryPerformanceCounter();
bool adbg_GetTickCount();

// Other
void adbg_CrashOllyDbg();

// Os
bool isSandboxDetected();
bool IsVM();
bool IsRdp();


// Exception
bool adbg_CloseHandleException();
bool adbg_SingleStepException();
bool adbg_Int3();
bool adbg_Int2D();
bool adbg_PrefixHop();
