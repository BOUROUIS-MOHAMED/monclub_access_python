@echo off
setlocal
title MB2000 / zkemkeeper dev scripts
set "HERE=%~dp0"

rem zkemkeeper.dll is 32-bit COM -> launch the 32-bit PowerShell directly.
set "PSX86=%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"

if exist "%PSX86%" (
  "%PSX86%" -NoProfile -ExecutionPolicy Bypass -File "%HERE%0_MENU.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%0_MENU.ps1"
)
endlocal
