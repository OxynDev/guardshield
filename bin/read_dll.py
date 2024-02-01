try:
    dll_bytes = open("AntiDBG.dll","rb").read()
    open("dll_bytes.txt","w").write("dll_bytes=b'''" + str(dll_bytes)[2:] + "''")
except:
    dll_bytes = open("bin/AntiDBG.dll","rb").read()
    open("bin/dll_bytes.txt","w").write("dll_bytes=b'''" + str(dll_bytes)[2:] + "''")