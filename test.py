import guardshield


# Custom function to be executed on debugger detection
def debugger_detected():
    print("Debugger detected!")

# Create a Security instance with desired settings
module = guardshield.Security(
    anti_debugger=True, # Enable debugger detection
    kill_on_debug=False, # Kill the application on detection
    custom_function_on_detection=debugger_detected # Execute custom function on detection
)

print(
module.check_security(),
module.isDebugged(),
module.check_vm()
)