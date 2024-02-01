import guardshield


# Custom function to be executed on debugger detection
def debugger_detected():
    print("Debugger detected!")

# Create a Security instance with desired settings
module = guardshield.Security(
    anti_debugger=False, # Enable debugger detection
    kill_on_debug=True, # Kill the application on detection
)

print(
"Ty print something xd"
)
module.anti_injection(python_dll='python38.dll')
while True:
    pass