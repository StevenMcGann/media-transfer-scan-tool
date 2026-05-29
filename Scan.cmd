@echo off
REM media-transfer-scan-tool — operator entry point.
REM Launches the 5.1-safe bootstrapper under Windows PowerShell, which then
REM resolves PowerShell 7.4+ (bundled or PATH) and runs the engine.
REM
REM Usage:  Scan.cmd -Path "D:\incoming\submission" [-Profile full] [...]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" %*
exit /b %ERRORLEVEL%
