import os, ctypes, threading, time, io, tempfile
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

        temp_file = tempfile.NamedTemporaryFile(suffix='.dll', delete=False)
        temp_file.write(dll_bytes)
        temp_file.close()
        self.dll = ctypes.WinDLL(temp_file.name)
        
            
    def check_security(self) -> None:

        if self.settings['anti_debugger'] == True:
            AntiDebugger(
                dll = self.dll,
                settings = self.settings
            )

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