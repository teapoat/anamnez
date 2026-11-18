@echo off
rem Launcher: bypasses PowerShell execution policy, script elevates itself (UAC)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0anamnez.ps1" %*
