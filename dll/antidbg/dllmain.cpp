#include "AntiDBG.h"
#include <iostream>
#include <vector>
#include <iostream>
#include <thread>
#include <windows.h>
#include <iostream>

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



typedef int (*OriginalFunc)(const char* name);

int FakePy_func(const char* name) {
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}

void HookFunction(LPCWSTR pythonDll, LPCSTR targetFunction) {
    HMODULE hPython = GetModuleHandle(pythonDll);
    
    if (hPython == NULL) {
        return;
    }

    OriginalFunc originalFunc = (OriginalFunc)GetProcAddress(hPython, targetFunction);
    if (originalFunc == NULL) {
        std::cout << "Function hooking error" << std::endl;
        return;
    }

    DWORD oldProtect;
    VirtualProtect(originalFunc, sizeof(OriginalFunc), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(originalFunc, FakePy_func, sizeof(OriginalFunc));
    VirtualProtect(originalFunc, sizeof(OriginalFunc), oldProtect, &oldProtect);
}



extern "C" {


    __declspec(dllexport) bool isDebugged() {
        std::vector<bool(*)()> functions = { adbg_IsDebuggerPresent, adbg_BeingDebuggedPEB, adbg_NtGlobalFlagPEB, adbg_CheckRemoteDebuggerPresent,
                                            adbg_NtQueryInformationProcess, adbg_CheckWindowClassName, adbg_CheckWindowName, adbg_ProcessFileName,
                                            adbg_NtSetInformationThread, adbg_HardwareDebugRegisters, adbg_MovSS, adbg_RDTSC,
                                            adbg_GetTickCount, adbg_CloseHandleException, adbg_SingleStepException, adbg_Int3, adbg_Int2D, adbg_PrefixHop };

        for (size_t i = 0; i < functions.size(); ++i) {
            bool result = functions[i]();
            if (result) {
                std::cout << i << std::endl;
                return true;
            }
        }
        return false;
    }

    __declspec(dllexport) int IsVm() {
        if (IsRdp() || IsVM())
            return true;
        else
            return false;

        return false;
    }

    __declspec(dllexport) int isSandbox() {
        if (isSandboxDetected())
            return true;
        else
            return false;

        return false;
    }

    __declspec(dllexport) int kill () {
        TerminateProcess(GetCurrentProcess(), 0);
        return 0;
    }

    __declspec(dllexport) int hookProtect(const wchar_t* pythonDll) {


        HookFunction(pythonDll, "PyRun_SimpleStringFlags");
        HookFunction(pythonDll, "Py_SetProgramName");
        HookFunction(pythonDll, "PyEval_InitThreads");
        HookFunction(pythonDll, "PyGILState_Release");
        HookFunction(pythonDll, "PyGILState_Ensure");

        return 0;
    }
}

