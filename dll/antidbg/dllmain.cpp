#include "AntiDBG.h"
#include <iostream>
#include <vector>
#include <iostream>
#include <thread>



bool adbg_IsDebuggerPresent();
bool adbg_BeingDebuggedPEB();
bool adbg_NtGlobalFlagPEB();
bool adbg_CheckRemoteDebuggerPresent();
bool adbg_NtQueryInformationProcess();
bool adbg_CheckWindowClassName();
bool adbg_CheckWindowName();
bool adbg_ProcessFileName();
bool adbg_NtSetInformationThread();
bool adbg_HardwareDebugRegisters();
bool adbg_MovSS();
bool adbg_RDTSC();
bool adbg_QueryPerformanceCounter();
bool adbg_GetTickCount();
bool adbg_CloseHandleException();
bool adbg_SingleStepException();
bool adbg_Int3();
bool adbg_Int2D();
bool adbg_PrefixHop();


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}


extern "C" {


    __declspec(dllexport) bool isDebugged() {
        std::vector<bool(*)()> functions = { adbg_IsDebuggerPresent, adbg_BeingDebuggedPEB, adbg_NtGlobalFlagPEB, adbg_CheckRemoteDebuggerPresent,
                                            adbg_NtQueryInformationProcess, adbg_CheckWindowClassName, adbg_CheckWindowName, adbg_ProcessFileName,
                                            adbg_NtSetInformationThread, adbg_HardwareDebugRegisters, adbg_MovSS, adbg_RDTSC, adbg_QueryPerformanceCounter,
                                            adbg_GetTickCount, adbg_CloseHandleException, adbg_SingleStepException, adbg_Int3, adbg_Int2D, adbg_PrefixHop };

        for (auto func : functions) {
            bool result = func();
            if (result == true) {
                return true;
            }
        }
        return false;
    }

    __declspec(dllexport) int kill () {
        TerminateProcess(GetCurrentProcess(), 0);
        return 0;
    }
}