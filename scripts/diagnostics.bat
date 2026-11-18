@echo off
setlocal

:menu
echo.
echo Windows Diagnostics
echo 1. Anamnez - collect logs and build report
echo 0. Exit
choice /c 10 /n /m "Select an option: "
if errorlevel 255 goto input_error
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 1

if not exist "%~dp0anamnez\anamnez.bat" goto missing
call "%~dp0anamnez\anamnez.bat" -FromMenu
goto menu

:missing
echo Anamnez launcher was not found next to this menu.
goto menu

:input_error
echo Could not read a menu choice.
pause
exit /b 1
