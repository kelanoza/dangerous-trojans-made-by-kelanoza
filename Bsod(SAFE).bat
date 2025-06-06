@echo off
@echo off
net session >nul 2>&1
if %errorLevel% == 0 (
    goto run
) else (
    echo Please run the application as administrator!
	timeout 3 /nobreak >nul
	exit
)

:run
taskkill /f /im wininit.exe
exit