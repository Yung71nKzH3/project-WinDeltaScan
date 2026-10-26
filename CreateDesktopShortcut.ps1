$wshShell = New-Object -ComObject WScript.Shell
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "WinDeltaScan.lnk"

# Use the current script directory dynamically
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$targetCmd = Join-Path $scriptDir "RunIncrementalScan.cmd"

$shortcut = $wshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetCmd
$shortcut.WorkingDirectory = $scriptDir
$shortcut.IconLocation = "$env:SystemRoot\System32\SecurityAndMaintenance.cpl,0"
$shortcut.Description = "Run Incremental Security Scan with Windows Defender"
$shortcut.Save()

Write-Host "Created Desktop Shortcut at: $shortcutPath" -ForegroundColor Green
