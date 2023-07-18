import os, ctypes, threading, time, io, tempfile, platform, subprocess, hashlib
from .dll_bytes import dll_bytes

timeout = 0.1


class AntiDebugger:

    def __init__(self, dll, settings):
        self.settings = settings
        self.dll = dll
        threading.Thread(target=self.start).start()

    def start(self) -> None:
        while True:

            if self.dll.isDebugged() == 0:
                pass
            else:
                function_check = self.settings['custom_function_on_detection']
                if function_check != None:
                    function_check()
                if self.settings['kill_on_debug'] == True:
                    self.dll.kill()
                

            time.sleep(timeout)

class Security:

    dll = None

    def __init__(self,
                    anti_debugger: bool = True,
                    kill_on_debug: bool = True,
                    custom_function_on_detection = None
                    
                 ):
        
        self.load_dll()

        self.settings = {
            "anti_debugger" : anti_debugger,
            "kill_on_debug" : kill_on_debug,
            "custom_function_on_detection" : custom_function_on_detection
        }

    def load_dll(self) -> None:
        #path = pkg_resources.resource_filename(__name__, 'lib.dll')

        temp_file = tempfile.NamedTemporaryFile(suffix='.dll', delete=True)
        temp_file.write(dll_bytes)
        self.dll = ctypes.WinDLL(temp_file.name)
        temp_file.close()
        
            
    def check_security(self) -> None:

        if self.settings['anti_debugger'] == True:
            AntiDebugger(
                dll = self.dll,
                settings = self.settings
            )

    def check_vm(self) -> bool:
        if self.dll.IsVm() == 0:
            return False
        else:
            return True

    def force_kill(self):
        self.dll.kill()
        os.close()
        exit()
        
    def isDebugged(self) -> bool:
        if self.dll.isDebugged() == 0:
            return False
        else:
            return True


    def isSandboxed(self) -> bool:
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
