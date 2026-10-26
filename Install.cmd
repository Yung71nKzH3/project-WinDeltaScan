@echo off
title WinDeltaScan Installer
echo ==========================================================
echo               WINDELTASCAN INSTALLER
echo ==========================================================
echo.
echo Creating Desktop shortcut...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0CreateDesktopShortcut.ps1"
echo.
echo ==========================================================
echo  Installation Complete!
echo  You can now launch WinDeltaScan directly from your Desktop.
echo ==========================================================
pause
