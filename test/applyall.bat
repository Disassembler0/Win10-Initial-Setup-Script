@ECHO OFF

powershell.exe -NoProfile -ExecutionPolicy Bypass -File %~dp0..\Win10.ps1 -preset "%~dp0applyall.preset"
