@echo off
setlocal
title MonClub - read-only C3 panel export
set "HERE=%~dp0"

rem plcommpro.dll is 32-bit -> launch the 32-bit PowerShell directly.
set "PSX86=%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"

if exist "%PSX86%" (
  "%PSX86%" -NoProfile -ExecutionPolicy Bypass -File "%HERE%export_c3_panel_readonly.ps1" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%export_c3_panel_readonly.ps1" %*
)
endlocal
