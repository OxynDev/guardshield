
dll_bytes = open("AntiDBG.dll","rb").read()
open("dll_bytes.txt","w").write(str(dll_bytes))