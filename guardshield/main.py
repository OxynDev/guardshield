from .dll_bytes import dll_bytes

import guardshield.utils.cheatengine as cheatengine
import guardshield.utils.dll_scan as dll_scan

import os, ctypes, threading, time, tempfile, platform, subprocess, hashlib
from ctypes import wintypes
import win32api

timeout = 0.1


class AntiDebugger:

    def __init__(self, dll, settings):
        self.settings = settings
        self.dll = dll
        threading.Thread(target=self.cpp_detector).start()
        threading.Thread(target=self.file_monitor).start()

    def cpp_detector(self) -> None:
        while True:

            if self.dll.isDebugged() == 0:
                pass
            else:
                function_check = self.settings['on_detection']
                if function_check != None:
                    function_check()
                if self.settings['kill_on_debug'] == True:
                    self.dll.kill()

            time.sleep(timeout)

    def file_monitor(self):
        res = cheatengine.monitor_dir(tempfile.gettempdir())
        if res == True:
            function_check = self.settings['on_detection']
            if function_check != None:
                function_check()
            if self.settings['kill_on_debug'] == True:
                self.dll.kill()


class Security:

    dll = None

    def __init__(self,
                    anti_debugger: bool = True,
                    kill_on_debug: bool = True,
                    detect_vm: bool = False,
                    detect_sandbox: bool = False,
                    on_detection = None
                    
                 ):
        
        self.load_dll()

        self.settings = {
            "anti_debugger" : anti_debugger,
            "kill_on_debug" : kill_on_debug,
            "on_detection" : on_detection,
            "detect_vm" : detect_vm,
            "detect_sandbox" : detect_sandbox,
        }

    def load_dll(self) -> None:
        #path = pkg_resources.resource_filename(__name__, 'lib.dll')

        temp_file = tempfile.NamedTemporaryFile(suffix='.dx', delete=False)
        os.add_dll_directory(os.path.dirname(temp_file.name))
        temp_file.write(dll_bytes)
        temp_file.close()
        self.dll = ctypes.CDLL(temp_file.name)
        
        op = wintypes.DWORD(0)
        baseAddress = ctypes.c_int(win32api.GetModuleHandle(None))
        ctypes.windll.kernel32.VirtualProtect(
            ctypes.pointer(baseAddress), 4096, 0x04, ctypes.pointer(op)
        )
        ctypes.memset(ctypes.pointer(baseAddress), 4096, ctypes.sizeof(baseAddress))

            
    def check_security(self) -> None:

        if self.settings['detect_vm'] == True:
            if self.check_vm() == True:
                
                function_check = self.settings['on_detection']
                
                if function_check != None: function_check()
                    
                return {
                    "detected":True, 
                    "description": "vm detected"
                    }
            
        if self.settings['detect_sandbox'] == True:
            if self.check_sandbox() == True:
                function_check = self.settings['on_detection']
                
                if function_check != None: function_check()
                    
                return {
                    "detected":True, 
                    "description": "sandbox detected"
                    }

        if self.settings['anti_debugger'] == True:
            AntiDebugger(
                dll = self.dll,
                settings = self.settings
            )

    def monitor_dll_bytes(self):
        
        res = dll_scan.check_dll_bytes()
        if res == True:
            
            function_check = self.settings['on_detection']
            if function_check != None: function_check()
            if self.settings['kill_on_debug'] == True: self.dll.kill()
                
            
            

    def anti_injection(self, python_dll: str):
        while True:
            try:
                self.dll.hookProtect(python_dll.encode('utf-16le'))
                break
            except:
                time.sleep(0.01)
                
        threading.Thread(target=self.monitor_dll_bytes).start()
            
    def check_vm(self) -> bool:
        if self.dll.IsVm() == 0:
            return False
        else:
            return True

    def force_kill(self):
        self.dll.kill()
        os.close()
        exit()
        
    def check_debug(self) -> bool:
        if self.dll.isDebugged() == 0:
            return False
        else:
            return True

    def check_sandbox(self) -> bool:
        if self.dll.isSandbox() == 0:
            return False
        else:
            return True

    def crash_pc(self) -> None:

        A=ctypes.POINTER(ctypes.c_int)()
        ctypes.windll.ntdll.RtlAdjustPrivilege(
            ctypes.c_uint(19),
            ctypes.c_uint(1),
            ctypes.c_uint(0),
            ctypes.byref(ctypes.c_int())
        )
        ctypes.windll.ntdll.NtRaiseHardError(
            ctypes.c_ulong(3221225595),
            ctypes.c_ulong(0),
            A,
            A,
            ctypes.c_uint(6),
            ctypes.byref(ctypes.c_uint())
        )
        
    def get_uuid(self) -> str:
        
        hash_value = 0
        for char in str(subprocess.check_output('wmic computersystem get model,manufacturer')):
            hash_value += ord(char)

        list_to_hash = [
            platform.machine(),
            platform.processor(),
            platform.win32_edition(),
            platform.win32_is_iot(),
            str(subprocess.check_output('wmic csproduct get uuid')).split(f'\\r\\n')[1].strip(f'\\r').strip(),
            str(hash_value),
            "hwid by guardshield"
        ]

        return hashlib.sha256(str(list_to_hash).encode()).hexdigest()
