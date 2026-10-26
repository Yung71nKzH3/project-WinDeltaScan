# WinDeltaScan 🛡️⚡

> **High-speed, on-demand incremental security scanner for Windows Defender.**  
> Scans **only** new and modified files across your drives—finishing in **seconds** instead of hours. Zero background resources.

---

## 💡 The Problem

Windows Defender gives users two extreme choices:
1. **Quick Scan:** Checks only running RAM and basic startup hooks (~2 minutes).
2. **Full Scan:** Blindly crawls and recalculates hashes for **every single file** on your storage drives (1 to 4 hours of heavy disk I/O and fan noise).

If you download an installer, extract an archive, or update game mods on `D:`, you shouldn't have to re-scan 500,000 unchanged Windows OS files just to verify the new files.

**WinDeltaScan bridges this gap.** It tracks file modifications at the filesystem layer and pipes **only the delta (changed/new files)** directly into Microsoft Defender's native engine (`MpCmdRun.exe`).

---

## 🚀 Features

- **⚡ Blazing Fast:** Scans your latest changes in **2 to 5 seconds** instead of running a multi-hour scan.
- **🔋 Zero Background Footprint:** No background services, no system tray bloat, no startup tasks. Consumes **0% CPU and 0 MB RAM** when not running.
- **🧠 Dual-Engine Hybrid Architecture:**
  - **Engine A (NTFS USN Journal):** Queries the kernel-level NTFS circular transaction log in **~2 milliseconds**. Completely ignores untouched directories and resists timestamp forgery ("timestomping").
  - **Engine B (.NET Watermark):** High-speed fallback for non-elevated user mode or non-NTFS volumes (FAT32, exFAT, external USBs).
- **🛡️ 100% Native Windows Defender:** Does not replace or conflict with Windows Defender Real-Time Protection. All scans are executed by Microsoft's verified antimalware engine.
- **🎯 Smart Filtering (`-HighRiskOnly`):** Skips volatile browser cache blocks (`.log`, `.dat`) and zeroes in on executables, scripts, archives, installers, and macro documents.
- **🖥️ One-Click Desktop Launcher:** Comes with a native desktop shortcut and an interactive terminal menu.

---

## 📊 Benchmark Results

Tested on a live Windows machine across **3,000 files** (50 mutated files, 2,950 untouched files):

| Approach | Detection Time | Precision | Recall | Requires Admin? |
| :--- | :---: | :---: | :---: | :---: |
| **NTFS USN Journal (Engine A)** | **~2.5 ms** | **100%** | **100%** | Yes (Admin) |
| **Timestamp Watermark (Engine B)** | **195 ms** | **100%** | **100%** | No |
| **Archive Bit (`+A`)** | 191 ms | 36% ⚠️ | 100% | No |
| **Traditional Full Crawl** | 112 ms | 1.7% 🛑 | 100% | No |

*Time to scan 50 delta files with Defender: **~3.2 seconds**.*  
*Time to scan 3,000 files individually: **~3.2 minutes**.*

---

## 🛠️ Installation & Quick Start

### 1. Download & Extract
Download `WinDeltaScan-v1.0.0.zip` from the [Releases](https://github.com/) page and extract it anywhere on your PC (e.g. `C:\Tools\WinDeltaScan` or `Documents`).

### 2. Run the Installer
Double-click **`Install.cmd`**.  
This creates a **WinDeltaScan** shortcut on your Desktop with the official Windows Security shield icon.

### 3. Scan Anytime
Whenever you want to run an incremental check:
1. Double-click the **WinDeltaScan** desktop shortcut.
2. Press **Enter** to run the **Quick Incremental Scan**.
3. It scans your new files in seconds and exits cleanly!

> **Pro-Tip (Max Speed):** Right-click the desktop shortcut and choose **"Run as administrator"** to activate **Engine A (NTFS USN Journal)**.

---

## 💻 CLI Usage

You can also run `WinDeltaScan.ps1` directly from PowerShell:

```powershell
# Run a Quick Incremental Scan (executables, scripts, installers)
.\WinDeltaScan.ps1 -Scan -HighRiskOnly

# Run a Deep Incremental Scan (all modified files, including documents & caches)
.\WinDeltaScan.ps1 -Scan

# Scan only a specific drive (e.g., secondary drive D:)
.\WinDeltaScan.ps1 -Scan -Drives D:

# View current checkpoints and drive filesystem status
.\WinDeltaScan.ps1 -Status

# Mark all existing files on disk as clean right now (Reset baseline)
.\WinDeltaScan.ps1 -ResetBaseline
```

---

## 📁 Repository Structure

```text
├── WinDeltaScan.ps1            # Core hybrid incremental engine
├── RunIncrementalScan.cmd      # Interactive batch menu launcher
├── Install.cmd                 # Double-click desktop shortcut installer
├── CreateDesktopShortcut.ps1   # PowerShell helper to create .lnk
├── LICENSE                     # MIT License
└── README.md                   # Documentation
```

---

## ⚖️ License

Distributed under the [MIT License](LICENSE).
