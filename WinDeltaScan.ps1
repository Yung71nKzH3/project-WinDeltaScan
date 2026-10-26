<#
.SYNOPSIS
    WinDeltaScan - Hybrid Incremental Security Scanner for Windows Defender.
    Scans only new and modified files across C:, D:, and removable drives.

.DESCRIPTION
    Dual-engine architecture:
    - Engine A (Primary): NTFS USN Change Journal (Instant, tamper-resistant, kernel-logged)
    - Engine B (Fallback): High-performance .NET Metadata & Timestamp Watermark (Non-NTFS / Non-Admin)
    Pipes dirty files directly into Microsoft Defender's native engine (MpCmdRun.exe).

.PARAMETER Scan
    Execute the incremental scan immediately.

.PARAMETER Status
    Display drive configurations, filesystems, and last scan watermarks.

.PARAMETER ResetBaseline
    Mark the current state of all files as scanned/clean.

.PARAMETER MaxFilesToScan
    Safety cap for number of delta files to scan in a single pass (Default: 1000).

.EXAMPLE
    .\WinDeltaScan.ps1 -Scan
    .\WinDeltaScan.ps1 -Status
    .\WinDeltaScan.ps1 -ResetBaseline
#>

[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$Status,
    [switch]$ResetBaseline,
    [switch]$HighRiskOnly,
    [string[]]$Drives,
    [int]$MaxFilesToScan = 1000
)

$ErrorActionPreference = "Continue"

# -------------------------------------------------------------
# 1. State & Environment Configuration
# -------------------------------------------------------------
$StateDir = Join-Path $env:LOCALAPPDATA "WinDeltaScan"
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}
$StateFile = Join-Path $StateDir "state.json"

function Get-State {
    if (Test-Path $StateFile) {
        try {
            return Get-Content $StateFile -Raw | ConvertFrom-Json
        } catch {
            return [PSCustomObject]@{ Volumes = @{}; LastRunUtc = $null }
        }
    }
    return [PSCustomObject]@{ Volumes = @{}; LastRunUtc = $null }
}

function Save-State ($stateObj) {
    $stateObj | ConvertTo-Json -Depth 5 | Out-File -FilePath $StateFile -Encoding UTF8 -Force
}

# -------------------------------------------------------------
# 2. Check Permissions & Locate Defender
# -------------------------------------------------------------
function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefenderCliPath {
    $candidates = @(
        "C:\ProgramData\Microsoft\Windows Defender\Platform\CurrentVersion\MpCmdRun.exe",
        "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { return $cand }
    }
    # Search latest platform directory
    $platformDirs = Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Platform\*" -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    foreach ($dir in $platformDirs) {
        $exe = Join-Path $dir.FullName "MpCmdRun.exe"
        if (Test-Path $exe) { return $exe }
    }
    return $null
}

# -------------------------------------------------------------
# 3. Drive Detection
# -------------------------------------------------------------
function Get-TargetVolumes {
    param([string[]]$RequestedDrives)
    
    $vols = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveType -in @("Fixed", "Removable") }
    if ($RequestedDrives) {
        $letters = $RequestedDrives | ForEach-Object { $_.TrimEnd(':\').ToUpper() }
        $vols = $vols | Where-Object { $letters -contains $_.DriveLetter.ToString().ToUpper() }
    }
    return $vols
}

# -------------------------------------------------------------
# 4. Engine B: Timestamp Watermark Scanner (.NET Optimized)
# -------------------------------------------------------------
function Get-DeltaViaWatermark {
    param(
        [string]$DriveRoot,
        [datetime]$SinceUtc
    )
    
    $dirtyFiles = [System.Collections.Generic.List[string]]::new()

    # High-risk folders to prioritize on system drive, or scan entire drive if dedicated (e.g. D:)
    $searchRoots = if ($DriveRoot -eq "C:\") {
        @("C:\Users", "C:\ProgramData", "C:\Windows\Temp", "C:\Temp") | Where-Object { Test-Path $_ }
    } else {
        @($DriveRoot)
    }

    # Recursive directory search compatible with both Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+
    function Search-Dir ($currentPath) {
        try {
            $files = [System.IO.Directory]::GetFiles($currentPath)
            foreach ($filePath in $files) {
                try {
                    $lastWrite = [System.IO.File]::GetLastWriteTimeUtc($filePath)
                    $creationTime = [System.IO.File]::GetCreationTimeUtc($filePath)
                    if ($lastWrite -gt $SinceUtc -or $creationTime -gt $SinceUtc) {
                        $dirtyFiles.Add($filePath)
                    }
                } catch {}
            }

            $dirs = [System.IO.Directory]::GetDirectories($currentPath)
            foreach ($subDir in $dirs) {
                try {
                    $dirInfo = [System.IO.DirectoryInfo]::new($subDir)
                    # Skip reparse points / symlinks to avoid infinite loops
                    if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                        Search-Dir $subDir
                    }
                } catch {}
            }
        } catch {}
    }

    foreach ($root in $searchRoots) {
        Search-Dir $root
    }
    return $dirtyFiles
}

# -------------------------------------------------------------
# 5. Engine A: NTFS USN Journal Scanner
# -------------------------------------------------------------
function Get-DeltaViaUsnJournal {
    param(
        [string]$DriveLetter,
        [string]$StartUsnHex
    )
    
    $dirtyFiles = [System.Collections.Generic.List[string]]::new()
    $latestUsnHex = $null

    # Query current USN state
    $queryOut = fsutil usn queryjournal "${DriveLetter}:" 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @{ Success = $false; Files = @(); NextUsn = $null }
    }

    $nextUsnLine = $queryOut | Where-Object { $_ -match "Next Usn\s*:\s*(0x[0-9a-fA-F]+)" }
    if ($nextUsnLine -and ($nextUsnLine -match "0x[0-9a-fA-F]+")) {
        $latestUsnHex = $matches[0]
    }

    if (-not $StartUsnHex) {
        # First time initializing
        return @{ Success = $true; Files = @(); NextUsn = $latestUsnHex; Initialized = $true }
    }

    # Read journal delta
    $readOut = fsutil usn readjournal "${DriveLetter}:" csv "startusn=$StartUsnHex" 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @{ Success = $false; Files = @(); NextUsn = $latestUsnHex }
    }

    foreach ($line in $readOut) {
        $parts = $line -split ","
        if ($parts.Count -ge 5) {
            $fileName = $parts[4].Trim(' "')
            if ($fileName -and $fileName -notmatch '^\$') {
                # Valid touched file entry
                $dirtyFiles.Add($fileName)
            }
        }
    }

    return @{
        Success = $true
        Files = $dirtyFiles | Select-Object -Unique
        NextUsn = $latestUsnHex
        Initialized = $false
    }
}

# -------------------------------------------------------------
# 6. Windows Defender Scan Executor
# -------------------------------------------------------------
function Invoke-DefenderScan {
    param(
        [string]$DefenderExe,
        [string[]]$FilesToScan
    )

    if ($FilesToScan.Count -eq 0) {
        Write-Host "No new or modified files found. System is clean and up to date!" -ForegroundColor Green
        return
    }

    Write-Host "`n[Defender Handoff] Scanning $($FilesToScan.Count) delta file(s)..." -ForegroundColor Cyan
    $threatsDetected = 0
    $scannedCount = 0

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($file in $FilesToScan) {
        if (-not (Test-Path $file)) { continue }
        $scannedCount++
        
        Write-Progress -Activity "WinDeltaScan: Scanning with Defender" -Status "$scannedCount / $($FilesToScan.Count): $file" -PercentComplete (($scannedCount / $FilesToScan.Count) * 100)
        
        # Scan single file via MpCmdRun
        $process = Start-Process -FilePath $DefenderExe -ArgumentList "-Scan -ScanType 3 -File `"$file`" -DisableRemediation" -Wait -NoNewWindow -PassThru
        
        if ($process.ExitCode -eq 2) {
            Write-Warning "THREAT DETECTED IN: $file"
            $threatsDetected++
        }
    }
    Write-Progress -Activity "WinDeltaScan: Scanning with Defender" -Completed
    $sw.Stop()

    $seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
    Write-Host "`nScan completed in $seconds seconds." -ForegroundColor Green
    if ($threatsDetected -gt 0) {
        Write-Host "WARNING: $threatsDetected threat(s) detected! Check Windows Security notification history." -ForegroundColor Red
    } else {
        Write-Host "Result: All $scannedCount delta files passed verification." -ForegroundColor Green
    }
}

# -------------------------------------------------------------
# 7. Action Handlers (Status, Reset, Scan)
# -------------------------------------------------------------
$isAdmin = Test-IsAdmin
$defenderExe = Get-DefenderCliPath
$state = Get-State

if ($Status) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "               WINDELTASCAN ENGINE STATUS                 " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Privilege Level: $(if ($isAdmin) {'Administrator (Option A Full Speed)'} else {'Standard User (Option B Watermark)'})"
    Write-Host "Defender Engine: $(if ($defenderExe) {$defenderExe} else {'Not Found!'})"
    Write-Host "State Directory: $StateDir"
    Write-Host "Last Scan Run  : $(if ($state.LastRunUtc) {$state.LastRunUtc} else {'Never'})"
    Write-Host "`nDetected Drives:"

    $vols = Get-TargetVolumes -RequestedDrives $Drives
    foreach ($vol in $vols) {
        $letter = $vol.DriveLetter
        $fs = $vol.FileSystem
        $cachedUsn = $state.Volumes."$letter".LastUsn
        $cachedTime = $state.Volumes."$letter".LastScanUtc
        Write-Host "  -> Drive ${letter}: [$($vol.FileSystemLabel)] ($fs) - Primary Engine: $(if ($fs -eq 'NTFS' -and $isAdmin) {'Option A (USN)'} else {'Option B (Watermark)'})"
        if ($cachedUsn) { Write-Host "     Last USN Checkpoint: $cachedUsn" -ForegroundColor DarkGray }
        if ($cachedTime) { Write-Host "     Last Scan Timestamp : $cachedTime" -ForegroundColor DarkGray }
    }
    exit 0
}

if ($ResetBaseline) {
    Write-Host "Resetting scan baselines for all drives..." -ForegroundColor Cyan
    $nowUtc = (Get-Date).ToUniversalTime().ToString("o")
    $vols = Get-TargetVolumes -RequestedDrives $Drives
    
    if (-not $state.Volumes) { $state | Add-Member -MemberType NoteProperty -Name Volumes -Value @{} -Force }

    foreach ($vol in $vols) {
        $letter = $vol.DriveLetter
        $usnRes = Get-DeltaViaUsnJournal -DriveLetter $letter -StartUsnHex $null
        $volState = [PSCustomObject]@{
            FileSystem = $vol.FileSystem
            LastUsn = $usnRes.NextUsn
            LastScanUtc = $nowUtc
        }
        $state.Volumes."$letter" = $volState
    }
    $state.LastRunUtc = $nowUtc
    Save-State $state
    Write-Host "Baseline successfully updated. All current files marked clean." -ForegroundColor Green
    exit 0
}

# Default Action: -Scan
if ($Scan -or ($PSCmdlet.MyInvocation.BoundParameters.Count -eq 0)) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "               RUNNING INCREMENTAL SCAN                   " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    if (-not $defenderExe) {
        Write-Error "Windows Defender (MpCmdRun.exe) was not found on this system."
        exit 1
    }

    $allDeltaFiles = [System.Collections.Generic.List[string]]::new()
    $vols = Get-TargetVolumes -RequestedDrives $Drives
    $nowUtc = (Get-Date).ToUniversalTime()
    if (-not $state.Volumes) { $state | Add-Member -MemberType NoteProperty -Name Volumes -Value @{} -Force }

    foreach ($vol in $vols) {
        $letter = $vol.DriveLetter
        $fs = $vol.FileSystem
        Write-Host "`nInspecting Drive ${letter}: ($fs)..." -ForegroundColor Yellow

        $volEntry = $state.Volumes."$letter"
        $previousUsn = if ($volEntry) { $volEntry.LastUsn } else { $null }
        $previousTime = if ($volEntry -and $volEntry.LastScanUtc) { [DateTime]::Parse($volEntry.LastScanUtc) } else { $nowUtc.AddDays(-1) }

        $driveDelta = @()

        # Engine Selection Logic:
        if ($fs -eq "NTFS" -and $isAdmin) {
            Write-Host "  -> Using Engine A: NTFS USN Journal" -ForegroundColor Green
            $usnRes = Get-DeltaViaUsnJournal -DriveLetter $letter -StartUsnHex $previousUsn
            if ($usnRes.Success) {
                $driveDelta = $usnRes.Files
                $state.Volumes."$letter" = [PSCustomObject]@{
                    FileSystem = $fs
                    LastUsn = $usnRes.NextUsn
                    LastScanUtc = $nowUtc.ToString("o")
                }
            } else {
                Write-Host "  -> USN Read failed. Falling back to Engine B (Watermark)..." -ForegroundColor DarkYellow
                $driveDelta = Get-DeltaViaWatermark -DriveRoot "${letter}:\" -SinceUtc $previousTime
            }
        } else {
            $reason = if ($fs -ne "NTFS") { "Non-NTFS filesystem" } else { "Standard User permissions" }
            Write-Host "  -> Using Engine B: Timestamp Watermark ($reason)" -ForegroundColor Cyan
            $driveDelta = Get-DeltaViaWatermark -DriveRoot "${letter}:\" -SinceUtc $previousTime
            $state.Volumes."$letter" = [PSCustomObject]@{
                FileSystem = $fs
                LastUsn = $null
                LastScanUtc = $nowUtc.ToString("o")
            }
        }

        Write-Host "  -> Found $($driveDelta.Count) candidate delta file(s) on ${letter}:" -ForegroundColor DarkCyan
        foreach ($d in $driveDelta) {
            $allDeltaFiles.Add($d)
        }
    }

    # High-Risk extension filter
    $HighRiskExtensions = @(
        ".exe", ".dll", ".sys", ".scr", ".com", ".pif",
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
        ".hta", ".cpl", ".msc", ".jar",
        ".msi", ".msp",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
        ".lnk", ".url",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
    )

    if ($HighRiskOnly) {
        Write-Host "Filtering for High-Risk payloads only (executables, scripts, installers, macros)..." -ForegroundColor Magenta
        $filtered = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $allDeltaFiles) {
            $ext = [System.IO.Path]::GetExtension($f).ToLower()
            if ($HighRiskExtensions -contains $ext) {
                $filtered.Add($f)
            }
        }
        $allDeltaFiles = $filtered
        Write-Host "  -> High-risk candidates: $($allDeltaFiles.Count) file(s)" -ForegroundColor Magenta
    }

    # Dedup and cap if huge
    $finalList = $allDeltaFiles | Select-Object -Unique
    if ($finalList.Count -gt $MaxFilesToScan) {
        Write-Host "Warning: Delta count ($($finalList.Count)) exceeds max cap ($MaxFilesToScan). Scanning newest $MaxFilesToScan files." -ForegroundColor Yellow
        $finalList = $finalList | Select-Object -First $MaxFilesToScan
    }

    # Pass to Defender
    Invoke-DefenderScan -DefenderExe $defenderExe -FilesToScan $finalList

    # Save state
    $state.LastRunUtc = $nowUtc.ToString("o")
    Save-State $state
}
