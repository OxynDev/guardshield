# GuardShield (Python security)

![Banner](https://github.com/OxynDev/guardshield/blob/dfe8d768d960576669baf31ae83ff22e016ccac2/temp/banner.png)

GuardShield is a Python library that provides robust security measures to protect your Python projects. It offers various detection methods to prevent debugging attempts and ensure secure execution of your code.

[Discord](https://discord.gg/8W6BweksGY)

## Installation

```python
pip install --force-reinstall guardshield
```

## Usage
Import the library:
```python
import guardshield
```

Enable anti-debugger detection and define custom actions on detection:
```python
# Custom function to be executed on debugger detection
def debugger_detected():
    print("Debugger detected!")

# Create a Security instance with desired settings
module = guardshield.Security(
    anti_debugger=True, # Enable debugger detection
    kill_on_debug=False, # Kill the application on detection
    detect_vm=False, # Call custom function on vm detection
    detect_sandbox=False, # Call custom function on sandbox detection
    on_detection=debugger_detected # Execute custom function on detection

)

# Start the security check loop in a separate thread
module.check_security() # -> dict { 'detected' : bool, 'description' : str }
```

Perform simple checks:
```python
# Check if the application is being debugged
module.check_debug() # -> bool

# Detect if the application is running within a sandbox environment (e.g., Sandboxie)
module.check_sandbox() # -> bool

# Terminate the application
module.force_kill() # -> None

# Detect if the application is running in vm and rdp
module.check_vm() # -> bool

# Crash user pc with Blue screen
module.crash_pc() # -> None

# Create pc fingerprint / hwid
module.get_uuid() # -> str

# Protect injection / hooking
module.anti_injection() # -> None

```

## Change log
```diff
v1.1.5 ⋮ 06/02/2024
+ bug fix
+ dll injection detection (by bytes)

v1.1.4 ⋮ 04/02/2024
+ bug fix
+ pyinject process detection (by name)

v1.1.3 ⋮ 01/02/2024
+ injection protection

v1.1.2 ⋮ 01/02/2024
+ false detection fix
```

## Better anti injection

https://www.youtube.com/watch?v=AP1rasewaUw&ab_channel=oxyn

## Secure Compilation and Protection Against Decompilation and Debugging Attacks

To ensure the security of your executable (`.exe`) file, it is recommended to avoid using PyInstaller for compilation, as it can be easily reversed. Instead, you can use "Nuitka," a source-to-source compiler that compiles Python code into optimized C source code, making it harder for checkers and reverse engineers to understand and modify your code.

Follow these steps to compile your code securely:

1. Obfuscate your code using tools like the [Pyobfuscate](https://pyob.oxyry.com/) website, which can obfuscate variable names and enhance protection.
2. Import GuardShield to prevent debugging during the execution of your code.
3. Compile the code using Nuitka. Here's an example command:

```python
python -m nuitka --follow-imports --onefile --standalone --windows-icon-from-ico=icon.ico main.py
```

After compiling the program, you can also provide it with additional protection using the vmprotect application.

By following these steps, your code will be well-protected. However, for the utmost security, consider keeping sensitive parts of your code on the server-side as an API and perform critical operations there. This approach adds an extra layer of protection and makes your application almost unbreakable.

## Request Encryption

To enhance the security of your API requests, it is recommended to encrypt the requests or add a fingerprint (custom hash) to the request that can be checked in the application and on the server. Here's an example of AES encryption using the `AESCipher` class:

```python
import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class Aes:
    def __init__(self):
        self.key = "SecKey2115"

    def decrypt(self, text, key=None):
        if key is not None:
            self.key = key
        return AESCipher(self.key).decrypt(text)

    def encrypt(self, text, key=None):
        if key is not None:
            self.key = key
        return AESCipher(self.key).encrypt(text).decode()
```

You can use the `Aes` class to encrypt and decrypt your requests using AES encryption. Remember to use a strong and secure key for encryption.


## Todo

- [x] Add sandboxie detection
- [x] Add Vm detection
- [x] Add Better cheat engine detection
- [x] Add DLL injection protection

      
## Tests

![Test 1](https://github.com/OxynDev/guardshield/blob/ac9b56845ff0deb4de33363abe4025e119e830b7/temp/1.gif)

![Test 2](https://github.com/OxynDev/guardshield/blob/4c971d7bebb2a04d54e7819561f5d850655a1881/temp/2.gif)

![Test 3](https://github.com/OxynDev/guardshield/blob/bd7c082bf12272f35e63988267df144039d70873/temp/3.gif)

![Test 4](https://github.com/OxynDev/guardshield/blob/4a13905d9b1ea1bbb84e5f72e2061a5347ee98a4/temp/4.gif)
