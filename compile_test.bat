python -m nuitka --follow-imports --onefile --standalone test.py

@REM for /d %%i in (*) do if "%%i" == "test.build" rd /s /q "%%i"
@REM for /d %%i in (*) do if "%%i" == "test.dist" rd /s /q "%%i"
@REM for /d %%i in (*) do if "%%i" == "test.onefile-build" rd /s /q "%%i"