@echo off
title WinDeltaScan - On-Demand Incremental Security Scanner
color 0b

:MENU
cls
echo ==========================================================
echo        WINDELTASCAN: ON-DEMAND INCREMENTAL SCANNER
echo ==========================================================
echo  Zero background resources. Runs only when you tell it to.
echo ==========================================================
echo.
echo  [1] Quick Incremental Scan  (Executables, scripts, installers - 2 to 5s)
echo  [2] Deep Incremental Scan   (ALL modified files, including docs & caches)
echo  [3] System Status            (Check drive checkpoints and last scan date)
echo  [4] Reset Baseline           (Mark all files clean right now)
echo  [5] Exit
echo.
set /p choice="Enter choice [1-5] (Press Enter for Quick Scan): "

if "%choice%"=="" set choice=1
if "%choice%"=="1" goto QUICK
if "%choice%"=="2" goto DEEP
if "%choice%"=="3" goto STATUS
if "%choice%"=="4" goto RESET
if "%choice%"=="5" goto EXIT
goto MENU

:QUICK
cls
echo Starting Quick Incremental Scan (High-Risk Payloads)...
echo.
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0WinDeltaScan.ps1" -Scan -HighRiskOnly
goto FINISH

:DEEP
cls
echo Starting Deep Incremental Scan (All Files)...
echo.
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0WinDeltaScan.ps1" -Scan
goto FINISH

:STATUS
cls
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0WinDeltaScan.ps1" -Status
goto FINISH

:RESET
cls
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0WinDeltaScan.ps1" -ResetBaseline
goto FINISH

:FINISH
echo.
echo ==========================================================
pause
goto MENU

:EXIT
exit /b
