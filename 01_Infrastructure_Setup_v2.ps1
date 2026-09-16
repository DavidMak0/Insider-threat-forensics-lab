<#
=====================================================================
 Apex Global Logistics Ltd - Infrastructure Setup Script (v2)
 Dissertation: Digital Forensics & Cyber Security Virtual Laboratory

 PURPOSE
 This script builds the core Active Directory infrastructure for the
 apex.local domain: Organisational Units, Security Groups, the 12
 employee accounts, departmental shared folders, and NTFS/share
 permissions.

 RUN ON: APEX-DC01, AFTER AD DS has been installed and the server has
 been promoted to a Domain Controller for apex.local.

 RUN AS: Domain Administrator (elevated PowerShell)

 NOTE: Run this ONCE on a clean domain. Re-running will attempt to
 recreate objects that already exist; existing objects are detected
 and skipped, but take a VirtualBox snapshot before running, and
 another snapshot immediately after, so you have a clean rollback
 point either way.

 CHANGELOG (v2)
  - Added Start-Transcript/Stop-Transcript logging for dissertation
    evidence (Recommendation 1)
  - Added try/catch around every AD/filesystem-modifying operation so
    a single failure doesn't silently break the run (Recommendation 2)
  - Added execution timing, printed in the summary (Recommendation 3)
  - Tightened SMB share-level permissions to the matching department
    group instead of Everyone, kept alongside NTFS restriction as
    defence in depth (Recommendation 4)
  - Added purpose comments above each loop (Recommendation 5)
=====================================================================
#>

# ---------------------------------------------------------------
# LOGGING START
# ---------------------------------------------------------------
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory | Out-Null
}
$LogPath = Join-Path $LogDir ("InfrastructureSetup_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Start-Transcript -Path $LogPath

$Start = Get-Date

Import-Module ActiveDirectory

# ---------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------

$DomainDN      = (Get-ADDomain).DistinguishedName   # e.g. DC=apex,DC=local
$SharesRoot    = "C:\Shares"
$DefaultPassword = ConvertTo-SecureString "Change me before running!" -AsPlainText -Force
# NOTE: This is a lab-only placeholder password for a fully isolated,
# internet-disconnected network. Do not reuse this value outside the lab.

$Departments = @("IT", "Operations", "Finance", "Human Resources", "Executive", "Procurement")

# Employee accounts: SamAccountName | FirstName | LastName | Department | JobTitle
$Users = @(
    @{ Sam = "d.roberts"; First = "Daniel";    Last = "Roberts";   Dept = "IT";              Title = "Senior Systems Administrator" }
    @{ Sam = "e.brooks";  First = "Emily";     Last = "Brooks";    Dept = "IT";              Title = "IT Support Technician" }
    @{ Sam = "j.carter";  First = "James";     Last = "Carter";    Dept = "Operations";      Title = "Senior Logistics Planning Analyst" }
    @{ Sam = "s.evans";   First = "Sarah";     Last = "Evans";     Dept = "Operations";      Title = "Logistics Coordinator" }
    @{ Sam = "r.green";   First = "Rebecca";   Last = "Green";     Dept = "Finance";         Title = "Finance Manager" }
    @{ Sam = "a.ali";     First = "Ahmed";     Last = "Ali";       Dept = "Finance";         Title = "Accounts Assistant" }
    @{ Sam = "j.wilson";  First = "Jennifer";  Last = "Wilson";    Dept = "Human Resources"; Title = "HR Manager" }
    @{ Sam = "p.moore";   First = "Paul";      Last = "Moore";     Dept = "Human Resources"; Title = "HR Officer" }
    @{ Sam = "c.anderson";First = "Charlotte"; Last = "Anderson";  Dept = "Executive";       Title = "Chief Executive Officer" }
    @{ Sam = "p.harris";  First = "Peter";     Last = "Harris";    Dept = "Executive";       Title = "Chief Financial Officer" }
    @{ Sam = "d.scott";   First = "David";     Last = "Scott";     Dept = "Procurement";     Title = "Procurement Manager" }
    @{ Sam = "e.thomas";  First = "Emma";      Last = "Thomas";    Dept = "Procurement";     Title = "Purchasing Officer" }
)

# Departmental shares (Public is separate, org-wide)
$DeptShares = @("Operations", "Finance", "HR", "Executive", "Procurement")

# Running counters for the summary / dissertation evidence
$ErrorsEncountered = 0

Write-Host "=== Starting Apex Global Logistics infrastructure build ===" -ForegroundColor Cyan

# ---------------------------------------------------------------
# 1. ORGANISATIONAL UNITS
# Purpose: create one OU per department to mirror the company's
# organisational structure and give each department a container to
# hold its users and security group.
# ---------------------------------------------------------------

Write-Host "`n[1/6] Creating Organisational Units..." -ForegroundColor Yellow

foreach ($Dept in $Departments) {
    try {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Dept'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $Dept -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "  Created OU: $Dept"
        } else {
            Write-Host "  OU already exists, skipping: $Dept"
        }
    } catch {
        Write-Warning "  Failed to create OU '$Dept': $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 2. SECURITY GROUPS (one per department, placed in matching OU)
# Purpose: provide a single group per department that both NTFS/share
# permissions and later GPOs can target, rather than assigning access
# to individual users.
# ---------------------------------------------------------------

Write-Host "`n[2/6] Creating Security Groups..." -ForegroundColor Yellow

foreach ($Dept in $Departments) {
    $GroupName = $Dept
    $OUPath = "OU=$Dept,$DomainDN"

    try {
        if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Path $OUPath -ErrorAction Stop
            Write-Host "  Created group: $GroupName"
        } else {
            Write-Host "  Group already exists, skipping: $GroupName"
        }
    } catch {
        Write-Warning "  Failed to create group '$GroupName': $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 3. USER ACCOUNTS
# Purpose: create the 12 employee accounts, place each in its
# department OU, and add it to the matching department security
# group so folder/share permissions apply automatically.
# ---------------------------------------------------------------

Write-Host "`n[3/6] Creating User Accounts..." -ForegroundColor Yellow

foreach ($U in $Users) {
    $DisplayName = "$($U.First) $($U.Last)"
    $OUPath = "OU=$($U.Dept),$DomainDN"
    $UPN = "$($U.Sam)@apex.local"

    try {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($U.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser `
                -Name $DisplayName `
                -GivenName $U.First `
                -Surname $U.Last `
                -SamAccountName $U.Sam `
                -UserPrincipalName $UPN `
                -Path $OUPath `
                -Department $U.Dept `
                -Title $U.Title `
                -Company "Apex Global Logistics Ltd" `
                -AccountPassword $DefaultPassword `
                -Enabled $true `
                -ChangePasswordAtLogon $true `
                -ErrorAction Stop

            Write-Host "  Created user: $DisplayName ($($U.Sam)) - $($U.Dept)"

            # Add user to their department security group
            Add-ADGroupMember -Identity $U.Dept -Members $U.Sam -ErrorAction Stop
        } else {
            Write-Host "  User already exists, skipping: $($U.Sam)"
        }
    } catch {
        Write-Warning "  Failed to create user '$DisplayName' ($($U.Sam)): $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 4. GIVE JAMES CARTER ACCESS TO SELECTED EXECUTIVE REPORTS
#    (legitimate elevated access, per the insider threat profile)
# Purpose: model the insider's real, legitimate access to Executive
# resources - the scenario depends on this access being authorised,
# not a misconfiguration.
# ---------------------------------------------------------------

Write-Host "`n[4/6] Granting James Carter access to the Executive group (legitimate access per scenario)..." -ForegroundColor Yellow
try {
    Add-ADGroupMember -Identity "Executive" -Members "j.carter" -ErrorAction Stop
    Write-Host "  j.carter added to Executive group"
} catch {
    Write-Warning "  Failed to add j.carter to Executive group: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 5. SHARED FOLDERS (filesystem + SMB share + NTFS permissions)
# Purpose: create one SMB share per department, restricted at both
# the share level and the NTFS level to the matching department
# group (defence in depth), plus an org-wide Public share.
# ---------------------------------------------------------------

Write-Host "`n[5/6] Creating shared folders..." -ForegroundColor Yellow

if (-not (Test-Path $SharesRoot)) {
    New-Item -Path $SharesRoot -ItemType Directory | Out-Null
}

# --- Departmental shares ---
foreach ($ShareName in $DeptShares) {
    $FolderPath = Join-Path $SharesRoot $ShareName

    try {
        if (-not (Test-Path $FolderPath)) {
            New-Item -Path $FolderPath -ItemType Directory | Out-Null
        }

        # Map share name back to its AD group name (HR share -> "Human Resources" group)
        $GroupName = switch ($ShareName) {
            "HR" { "Human Resources" }
            default { $ShareName }
        }

        # Create SMB share if it doesn't already exist.
        # Share-level access is restricted to the matching department
        # group plus Domain Admins (for administration), rather than
        # Everyone - NTFS below applies the same restriction again as
        # defence in depth.
        if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $ShareName -Path $FolderPath `
                -ChangeAccess "APEX\$GroupName" `
                -FullAccess "APEX\Domain Admins" `
                -ErrorAction Stop | Out-Null
            Write-Host "  Created share: \\APEX-DC01\$ShareName (access: APEX\$GroupName)"
        }

        # NTFS: department group gets Modify on its own folder
        $Acl = Get-Acl $FolderPath
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "APEX\$GroupName", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.AddAccessRule($Rule)
        Set-Acl -Path $FolderPath -AclObject $Acl -ErrorAction Stop
        Write-Host "  NTFS Modify granted to APEX\$GroupName on $ShareName"
    } catch {
        Write-Warning "  Failed to configure share '$ShareName': $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# --- Public share (all authenticated users, read/write) ---
try {
    $PublicPath = Join-Path $SharesRoot "Public"
    if (-not (Test-Path $PublicPath)) {
        New-Item -Path $PublicPath -ItemType Directory | Out-Null
    }
    if (-not (Get-SmbShare -Name "Public" -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name "Public" -Path $PublicPath `
            -ChangeAccess "Authenticated Users" `
            -FullAccess "APEX\Domain Admins" `
            -ErrorAction Stop | Out-Null
        Write-Host "  Created share: \\APEX-DC01\Public (access: Authenticated Users)"
    }
    $Acl = Get-Acl $PublicPath
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Authenticated Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.AddAccessRule($Rule)
    Set-Acl -Path $PublicPath -AclObject $Acl -ErrorAction Stop
    Write-Host "  NTFS Modify granted to Authenticated Users on Public"
} catch {
    Write-Warning "  Failed to configure Public share: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 6. SUMMARY
# ---------------------------------------------------------------

$Finish = Get-Date
$Duration = $Finish - $Start

Write-Host "`n[6/6] Build summary" -ForegroundColor Yellow
Write-Host "  OUs created:        $($Departments.Count)"
Write-Host "  Groups created:     $($Departments.Count)"
Write-Host "  Users created:      $($Users.Count)"
Write-Host "  Shares created:     $($DeptShares.Count + 1) (including Public)"
Write-Host "  Errors encountered: $ErrorsEncountered"
Write-Host "  Execution time:     $($Duration.ToString())"

Write-Host "`n=== Infrastructure build complete ===" -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Verify objects in Active Directory Users and Computers (dsa.msc)"
Write-Host "  2. Verify shares are reachable from APEX-WS01 (\\APEX-DC01\Public etc.)"
Write-Host "  3. Take a VirtualBox snapshot: 'Post-Infrastructure-Build'"
Write-Host "  4. Proceed to Script 02: Enterprise Population"
Write-Host "`nFull execution log saved to: $LogPath" -ForegroundColor Cyan

Stop-Transcript
