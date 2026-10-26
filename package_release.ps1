$version = "v1.0.0"
$zipName = "WinDeltaScan-$version.zip"
$filesToZip = @(
    "WinDeltaScan.ps1",
    "RunIncrementalScan.cmd",
    "Install.cmd",
    "CreateDesktopShortcut.ps1",
    "README.md",
    "LICENSE"
)

Write-Host "Packaging $zipName..." -ForegroundColor Cyan

if (Test-Path $zipName) {
    Remove-Item $zipName -Force
}

Compress-Archive -Path $filesToZip -DestinationPath $zipName -Force

Write-Host "Successfully packaged: $zipName" -ForegroundColor Green
Write-Host "File size: $((Get-Item $zipName).Length / 1KB) KB"
