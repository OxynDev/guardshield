# [UPDATE FIX TOMORROW] GuardShield ( python security )

GuardShield is a Python library that utilizes C++ to detect whether the current Python project is being debugged and provides an easy way to prevent it. With a wide range of 20 detection methods, GuardShield offers robust protection against debugging attempts, ensuring secure exe execution.


## Installation

```python
pip install guardshield
```


## Usage
Import 
```python
import guardshield
```
Anti debugger detection loop
```python
# Custom own function
def debbuger_detected():
    print("skid")

module = guardshield.Security(
    anti_debugger=True, # Debbuger detection
    kill_on_debug=True, # Kill app on detection
    custom_function_on_detection=debbuger_detected # Called function on detection
    )
    
# Loop in thread
module.check_security()
```
Simple check
```python
module.isDebugged()
```
Kill app
```python
module.kill()
```

## How to Compile Your Files Securely and Protect Against Decompilation and Debugging Attacks?

If you want your exe file to be secure, you should avoid using PyInstaller to compile your Python file into an executable, as this process can be easily reversed. To maintain the source code of our program and make it difficult for checkers/reverse engineers, we should use "Nuitka".

Nuitka is a source-to-source compiler that compiles Python code into C source code, applying certain compile-time optimizations such as constant folding and propagation, built-in call prediction, type inference, and conditional execution.

The first step is to obfuscate our code using tools like this website, which allows for variable name obfuscation (e.g., https://pyob.oxyry.com/). After obfuscating the code, we can further enhance the protection by importing GuardShield to prevent debugging.

The next step is to compile the code using Nuitka. Here's an example command:

```python
python -m nuitka --follow-imports --onefile --standalone --include-package-data=guardshield --windows-icon-from-ico=icon.ico main.py
```

After completing these three steps, our code will be well-protected. However, it's important to note that the best way to secure our application is to keep part of the code on the server-side as an API and perform certain operations there. This approach will result in an almost unbreakable application.
