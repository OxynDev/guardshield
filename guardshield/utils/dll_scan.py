
import ctypes.wintypes
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAX_MODULE_NAME32 = 255

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("GlblcntUsage", ctypes.wintypes.DWORD),
        ("ProccntUsage", ctypes.wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", ctypes.wintypes.DWORD),
        ("hModule", ctypes.wintypes.HMODULE),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * ctypes.wintypes.MAX_PATH)
    ]


def read_bytes_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()
    
def check_dll_bytes():
    
    current_process = ctypes.windll.kernel32.GetCurrentProcessId()

    while True:
        
        blacklisted = ['PyInjector',"exec(base64.b64decode(b'","r.title('Python shell')",'de4pyhook3','DE4PYHOOKEEEEE99']
        all_flags = ['Py_SetProgramName','PyEval_InitThreads','PyGILState_Ensure','Python311.dll','Python310.dll','Python39.dll','Python38.dll','Python37.dll','_pthread_cleanup_dest','_Unwind_GetRegionStart','_pthread_tryjoin','pthread_rwlock_tryrdlock','_pthread_rel_time_in_ms','_Unwind_Resume','__emutls_register_common','pthread_timechange_handler_np','_Unwind_Resume_or_Rethrow']

        process_handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, current_process)

        if process_handle:
            try:
                me32 = MODULEENTRY32()
                me32.dwSize = ctypes.sizeof(MODULEENTRY32)
                snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(8, current_process)
                if snapshot != -1:
                    result = ctypes.windll.kernel32.Module32First(snapshot, ctypes.byref(me32))
                    
                    while result:
                        
                        detections = 0
                        module_path = me32.szExePath.decode()
                        
                        if module_path.endswith('.dll'):
                            module_bytes = read_bytes_from_file(module_path)
                            
                            for bl in blacklisted:
                                if (bytes(bl, encoding="utf8") in module_bytes):
                                    return True
                                    
                            for flag in all_flags:
                                if (bytes(flag, encoding="utf8") in module_bytes):
                                    detections += 1
                                
                            if detections >= 5:
                                return True

                        result = ctypes.windll.kernel32.Module32Next(snapshot, ctypes.byref(me32))
                    ctypes.windll.kernel32.CloseHandle(snapshot)

            finally:
                ctypes.windll.kernel32.CloseHandle(process_handle)

        time.sleep(0.0001)
