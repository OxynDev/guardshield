import guardshield


# Custom function to be executed on debugger detection
def debugger_detected():
    print("Debugger detected!")

# Create a Security instance with desired settings
module = guardshield.Security(
    anti_debugger=True, # Enable debugger detection
    kill_on_debug=True, # Kill the application on detection
)

print(
module.check_security(),
module.check_vm()
)