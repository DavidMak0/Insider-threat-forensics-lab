<#
=====================================================================
 Apex Global Logistics Ltd - Enterprise Population Script (Script 02)
 Dissertation: Digital Forensics & Cyber Security Virtual Laboratory

 PURPOSE
 Populates the departmental shares created by Script 01 with realistic
 business documents backdated across a three-month operational period
 (May-July 2026), per the Script 02 Detailed File & Ownership Plan.
 No malicious activity is performed in this script - that is reserved
 for Script 03.

 RUN ON: APEX-DC01, AFTER Script 01 has completed successfully.
 RUN AS: Domain Administrator (elevated PowerShell)

 NOTE ON THE IT SHARE
 Script 01's share-creation loop did not include an "IT" share (only
 Operations, Finance, HR, Executive and Procurement were created,
 alongside Public). This script creates the missing IT share itself
 -- folder, SMB share, and NTFS permissions for the IT group -- before
 populating it, so the plan's IT files have somewhere to live. If you
 later re-run Script 01, this won't cause a conflict, as Script 01's
 own existence checks will simply skip shares that already exist.
=====================================================================
#>

# ---------------------------------------------------------------
# LOGGING START
# ---------------------------------------------------------------
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogPath = Join-Path $LogDir ("EnterprisePopulation_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Start-Transcript -Path $LogPath

$Start = Get-Date
$ErrorsEncountered = 0
$FilesCreated = 0

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ---------------------------------------------------------------
# 0. CONFIGURATION
# ---------------------------------------------------------------

$SharesRoot = "C:\Shares"
$DomainDN   = (Get-ADDomain).DistinguishedName

# Full names for author/owner metadata, keyed by SamAccountName
$OwnerNames = @{
    "d.roberts" = "Daniel Roberts"; "e.brooks" = "Emily Brooks"; "j.carter" = "James Carter"
    "s.evans" = "Sarah Evans"; "r.green" = "Rebecca Green"; "a.ali" = "Ahmed Ali"
    "j.wilson" = "Jennifer Wilson"; "p.moore" = "Paul Moore"; "c.anderson" = "Charlotte Anderson"
    "p.harris" = "Peter Harris"; "d.scott" = "David Scott"; "e.thomas" = "Emma Thomas"
    "it.central" = "IT Department"
}

# ---------------------------------------------------------------
# 1. ENSURE THE IT SHARE EXISTS (missing from Script 01)
# ---------------------------------------------------------------

Write-Host "=== Starting Apex Global Logistics enterprise population ===" -ForegroundColor Cyan
Write-Host "`n[1/4] Ensuring IT share exists (not created by Script 01)..." -ForegroundColor Yellow

try {
    $ItFolder = Join-Path $SharesRoot "IT"
    if (-not (Test-Path $ItFolder)) {
        New-Item -Path $ItFolder -ItemType Directory | Out-Null
    }
    if (-not (Get-SmbShare -Name "IT" -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name "IT" -Path $ItFolder `
            -ChangeAccess "APEX\IT" `
            -FullAccess "APEX\Domain Admins" `
            -ErrorAction Stop | Out-Null
        Write-Host "  Created share: \\APEX-DC01\IT (access: APEX\IT)"
    } else {
        Write-Host "  IT share already exists, skipping creation."
    }
    $Acl = Get-Acl $ItFolder
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "APEX\IT", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.AddAccessRule($Rule)
    Set-Acl -Path $ItFolder -AclObject $Acl
    Write-Host "  NTFS Modify granted to APEX\IT on IT share"
} catch {
    Write-Warning "  Failed to create/verify IT share: $($_.Exception.Message)"
    $ErrorsEncountered++
}

# ---------------------------------------------------------------
# 2. FILE-BUILDING HELPER FUNCTIONS
# Purpose: construct genuinely valid, minimal .docx / .xlsx / .pdf
# files from scratch (not renamed text files), including author
# metadata set to the correct file owner - a real forensic artefact.
# ---------------------------------------------------------------

function New-MinimalDocx {
    param(
        [string]$Path,
        [string[]]$Paragraphs,
        [string]$Owner,
        [datetime]$Created
    )
    $iso = $Created.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $bodyXml = ($Paragraphs | ForEach-Object {
        $escaped = $_ -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
        "<w:p><w:r><w:t xml:space=`"preserve`">$escaped</w:t></w:r></w:p>"
    }) -join ""

    $contentTypes = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>
"@

    $rootRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>
"@

    $docRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"@

    $documentXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><w:document xmlns:w=`"http://schemas.openxmlformats.org/wordprocessingml/2006/main`"><w:body>$bodyXml</w:body></w:document>"

    $stylesXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><w:styles xmlns:w=`"http://schemas.openxmlformats.org/wordprocessingml/2006/main`"><w:docDefaults/></w:styles>"

    $coreXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:creator>$Owner</dc:creator>
<cp:lastModifiedBy>$Owner</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">$iso</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">$iso</dcterms:modified>
</cp:coreProperties>
"@

    if (Test-Path $Path) { Remove-Item $Path -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Add-ZipEntryText -Zip $zip -EntryName "[Content_Types].xml" -Text $contentTypes
        Add-ZipEntryText -Zip $zip -EntryName "_rels/.rels" -Text $rootRels
        Add-ZipEntryText -Zip $zip -EntryName "word/document.xml" -Text $documentXml
        Add-ZipEntryText -Zip $zip -EntryName "word/styles.xml" -Text $stylesXml
        Add-ZipEntryText -Zip $zip -EntryName "word/_rels/document.xml.rels" -Text $docRels
        Add-ZipEntryText -Zip $zip -EntryName "docProps/core.xml" -Text $coreXml
    } finally {
        $zip.Dispose()
    }
}

function New-MinimalXlsx {
    param(
        [string]$Path,
        [string]$SheetName,
        [array]$Rows,          # array of arrays of cell values (row 1 = header)
        [string]$Owner,
        [datetime]$Created
    )
    $iso = $Created.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $rowNum = 0
    $sheetDataXml = ($Rows | ForEach-Object {
        $rowNum++
        $rowArr = $_
        $cellsXml = ($rowArr | ForEach-Object {
            $escaped = ([string]$_) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
            "<c t=`"inlineStr`"><is><t xml:space=`"preserve`">$escaped</t></is></c>"
        }) -join ""
        "<row r=`"$rowNum`">$cellsXml</row>"
    }) -join ""

    $contentTypes = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>
"@

    $rootRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>
"@

    $workbookXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><workbook xmlns=`"http://schemas.openxmlformats.org/spreadsheetml/2006/main`" xmlns:r=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships`"><sheets><sheet name=`"$SheetName`" sheetId=`"1`" r:id=`"rId1`"/></sheets></workbook>"

    $workbookRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>
"@

    $sheetXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><worksheet xmlns=`"http://schemas.openxmlformats.org/spreadsheetml/2006/main`"><sheetData>$sheetDataXml</sheetData></worksheet>"

    $coreXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:creator>$Owner</dc:creator>
<cp:lastModifiedBy>$Owner</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">$iso</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">$iso</dcterms:modified>
</cp:coreProperties>
"@

    if (Test-Path $Path) { Remove-Item $Path -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Add-ZipEntryText -Zip $zip -EntryName "[Content_Types].xml" -Text $contentTypes
        Add-ZipEntryText -Zip $zip -EntryName "_rels/.rels" -Text $rootRels
        Add-ZipEntryText -Zip $zip -EntryName "xl/workbook.xml" -Text $workbookXml
        Add-ZipEntryText -Zip $zip -EntryName "xl/_rels/workbook.xml.rels" -Text $workbookRels
        Add-ZipEntryText -Zip $zip -EntryName "xl/worksheets/sheet1.xml" -Text $sheetXml
        Add-ZipEntryText -Zip $zip -EntryName "docProps/core.xml" -Text $coreXml
    } finally {
        $zip.Dispose()
    }
}

function Add-ZipEntryText {
    param($Zip, [string]$EntryName, [string]$Text)
    $entry = $Zip.CreateEntry($EntryName)
    $stream = $entry.Open()
    $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
    $writer.Write($Text)
    $writer.Flush()
    $writer.Dispose()
    $stream.Dispose()
}

function New-SimplePdf {
    param([string]$Path, [string[]]$Lines, [string]$Title)

    $encoding = [System.Text.Encoding]::ASCII
    $objects = New-Object System.Collections.Generic.List[byte[]]

    $textOps = "BT /F1 12 Tf 50 740 Td 14 TL`n"
    $first = $true
    foreach ($line in $Lines) {
        $escaped = $line -replace '\\','\\\\' -replace '\(','\(' -replace '\)','\)'
        if ($first) {
            $textOps += "($escaped) Tj`n"
            $first = $false
        } else {
            $textOps += "T* ($escaped) Tj`n"
        }
    }
    $textOps += "ET"

    $obj1 = "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
    $obj2 = "2 0 obj`n<< /Type /Pages /Kids [3 0 R] /Count 1 >>`nendobj`n"
    $obj3 = "3 0 obj`n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>`nendobj`n"
    $obj4 = "4 0 obj`n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`nendobj`n"
    $streamBytes = $encoding.GetBytes($textOps)
    $obj5 = "5 0 obj`n<< /Length $($streamBytes.Length) >>`nstream`n$textOps`nendstream`nendobj`n"

    $header = "%PDF-1.4`n"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($header)

    $offsets = @(0)  # object 0 placeholder
    $pos = $encoding.GetByteCount($header)

    foreach ($obj in @($obj1, $obj2, $obj3, $obj4, $obj5)) {
        $offsets += $pos
        [void]$sb.Append($obj)
        $pos += $encoding.GetByteCount($obj)
    }

    $xrefOffset = $pos
    $xref = "xref`n0 6`n0000000000 65535 f `n"
    for ($i = 1; $i -le 5; $i++) {
        $xref += "{0:D10} 00000 n `n" -f $offsets[$i]
    }
    $trailer = "trailer`n<< /Size 6 /Root 1 0 R >>`nstartxref`n$xrefOffset`n%%EOF"

    [void]$sb.Append($xref)
    [void]$sb.Append($trailer)

    if (Test-Path $Path) { Remove-Item $Path -Force }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $encoding)
}

function Set-BackdatedTimestamp {
    param([string]$Path, [datetime]$Date)
    try {
        $item = Get-Item $Path
        $item.CreationTime = $Date
        $item.LastWriteTime = $Date
        $item.LastAccessTime = $Date
    } catch {
        Write-Warning "  Could not backdate timestamp for $Path : $($_.Exception.Message)"
    }
}

function Set-FileOwnerBestEffort {
    param([string]$Path, [string]$SamAccountName)
    try {
        $acl = Get-Acl $Path
        $acl.SetOwner([System.Security.Principal.NTAccount]"APEX\$SamAccountName")
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
    } catch {
        # Non-fatal: ownership assignment can fail depending on token
        # privileges. NTFS content/permissions are unaffected either way.
        Write-Warning "  Could not set NTFS owner to $SamAccountName on $Path (non-fatal)"
    }
}

function Get-RandomDateInMonth {
    param([int]$Year, [int]$Month, [int]$FromDay = 1, [int]$ToDay = 0)
    if ($ToDay -eq 0) { $ToDay = [DateTime]::DaysInMonth($Year, $Month) }
    $day = Get-Random -Minimum $FromDay -Maximum ($ToDay + 1)
    $hour = Get-Random -Minimum 8 -Maximum 18
    $minute = Get-Random -Minimum 0 -Maximum 60
    return Get-Date -Year $Year -Month $Month -Day $day -Hour $hour -Minute $minute -Second 0
}

# ---------------------------------------------------------------
# 3. FILE MANIFEST
# Purpose: single source of truth for every file to be generated,
# matching the Script 02 Detailed File & Ownership Plan exactly.
# Month: 5 = May, 6 = June, 7 = July (2026). LateJuly restricts July
# files to the 20th-31st, reflecting "most recent/current" data.
# ---------------------------------------------------------------

$Manifest = @(
    # --- IT ---
    @{ Share="IT"; File="Server Inventory.xlsx"; Type="xlsx"; Owner="d.roberts"; Month=5
       Rows=@(@("Server Name","Role","IP Address"),@("APEX-DC01","Domain Controller","192.168.100.1"),@("APEX-WS01","Workstation","192.168.100.10"),@("APEX-FS01","File Server (Planned)","192.168.100.30")) }
    @{ Share="IT"; File="Network Diagram.pdf"; Type="pdf"; Owner="d.roberts"; Month=5
       Lines=@("Apex Global Logistics Ltd","Network Topology Overview","","Domain: apex.local","Core segment: 192.168.100.0/24","Domain Controller: APEX-DC01 (.1)","Workstations: APEX-WS01 and future rollout (.10 - .49)") }
    @{ Share="IT"; File="Backup Schedule.docx"; Type="docx"; Owner="e.brooks"; Month=6
       Paragraphs=@("Apex Global Logistics Ltd - Backup Schedule","","Full backups are performed weekly on Sunday evenings.","Incremental backups run daily at 22:00.","Backup retention period is 90 days.","Restoration tests are conducted on the first Monday of each month.") }
    @{ Share="IT"; File="Password Policy.pdf"; Type="pdf"; Owner="d.roberts"; Month=5
       Lines=@("Apex Global Logistics Ltd","IT Password Policy","","Minimum length: 12 characters","Complexity: required","Maximum age: 90 days","Account lockout after 5 failed attempts") }

    # --- Operations ---
    @{ Share="Operations"; File="Delivery Schedule.xlsx"; Type="xlsx"; Owner="j.carter"; Month=7; LateJuly=$true
       Rows=@(@("Route","Customer","Scheduled Date"),@("R-102","Meridian Retail Group","2026-07-22"),@("R-118","Northfield Distribution","2026-07-24"),@("R-131","Castlebridge Logistics Partners","2026-07-27")) }
    @{ Share="Operations"; File="Warehouse Report.docx"; Type="docx"; Owner="s.evans"; Month=6
       Paragraphs=@("Apex Global Logistics Ltd - Monthly Warehouse Report","","Warehouse throughput increased by 6% compared to the previous month.","Pallet capacity utilisation currently sits at 78%.","No significant stock discrepancies were identified during the monthly audit.") }
    @{ Share="Operations"; File="Vehicle Checklist.xlsx"; Type="xlsx"; Owner="s.evans"; Month=6
       Rows=@(@("Vehicle ID","Last Inspection","Status"),@("APX-VAN-01","2026-06-03","Passed"),@("APX-VAN-02","2026-06-04","Passed"),@("APX-HGV-01","2026-06-10","Minor Fault - Scheduled")) }
    @{ Share="Operations"; File="Shift Rota.xlsx"; Type="xlsx"; Owner="s.evans"; Month=7
       Rows=@(@("Employee","Shift","Days"),@("S. Evans","Day","Mon-Fri"),@("Warehouse Team A","Day","Mon-Fri"),@("Warehouse Team B","Night","Mon-Fri")) }

    # --- Finance ---
    @{ Share="Finance"; File="Payroll_May.xlsx"; Type="xlsx"; Owner="a.ali"; Month=5
       Rows=@(@("Department","Headcount","Total Payroll (GBP)"),@("Operations","220","412,000"),@("Finance","18","61,500"),@("Executive","4","78,000")) }
    @{ Share="Finance"; File="Payroll_June.xlsx"; Type="xlsx"; Owner="a.ali"; Month=6
       Rows=@(@("Department","Headcount","Total Payroll (GBP)"),@("Operations","224","418,600"),@("Finance","18","61,500"),@("Executive","4","78,000")) }
    @{ Share="Finance"; File="Payroll_July.xlsx"; Type="xlsx"; Owner="a.ali"; Month=7
       Rows=@(@("Department","Headcount","Total Payroll (GBP)"),@("Operations","226","421,900"),@("Finance","18","61,500"),@("Executive","4","78,000")) }
    @{ Share="Finance"; File="Budget_2026.xlsx"; Type="xlsx"; Owner="r.green"; Month=5
       Rows=@(@("Department","Annual Budget (GBP)"),@("Operations","5,200,000"),@("Finance","740,000"),@("Procurement","3,100,000"),@("HR","480,000")) }
    @{ Share="Finance"; File="Quarterly_Forecast.xlsx"; Type="xlsx"; Owner="r.green"; Month=7; LateJuly=$true
       Rows=@(@("Quarter","Forecast Revenue (GBP)","Notes"),@("Q3 2026","4,850,000","Growth driven by new contracts"),@("Q4 2026 (Projected)","5,100,000","Pending confirmation")) }

    # --- Human Resources ---
    @{ Share="HR"; File="Employee Handbook.pdf"; Type="pdf"; Owner="j.wilson"; Month=5
       Lines=@("Apex Global Logistics Ltd","Employee Handbook","","Section 1: Code of Conduct","Section 2: Working Hours and Leave","Section 3: Health and Safety","Section 4: IT Acceptable Use Policy") }
    @{ Share="HR"; File="Leave Requests.xlsx"; Type="xlsx"; Owner="p.moore"; Month=6
       Rows=@(@("Employee","Dates","Status"),@("S. Evans","10-14 Aug 2026","Approved"),@("D. Scott","22-23 Jun 2026","Approved"),@("E. Thomas","5-9 Aug 2026","Pending")) }
    @{ Share="HR"; File="Recruitment Tracker.docx"; Type="docx"; Owner="j.wilson"; Month=6
       Paragraphs=@("Apex Global Logistics Ltd - Recruitment Tracker","","Open role: Warehouse Operative x2 - interviews scheduled","Open role: Finance Assistant - offer extended","Open role: Fleet Technician - awaiting sign-off") }
    @{ Share="HR"; File="Training Records.xlsx"; Type="xlsx"; Owner="p.moore"; Month=7
       Rows=@(@("Employee","Course","Completed"),@("S. Evans","Manual Handling Refresher","2026-07-08"),@("E. Brooks","Cyber Security Awareness","2026-07-15"),@("D. Scott","GDPR Fundamentals","2026-07-18")) }

    # --- Executive ---
    @{ Share="Executive"; File="Board Minutes - May 2026.docx"; Type="docx"; Owner="c.anderson"; Month=5
       Paragraphs=@("Apex Global Logistics Ltd - Board Minutes","May 2026","","Attendees: C. Anderson, P. Harris","Q1 performance reviewed and approved.","Discussion of warehouse capacity constraints.") }
    @{ Share="Executive"; File="Board Minutes - June 2026.docx"; Type="docx"; Owner="c.anderson"; Month=6
       Paragraphs=@("Apex Global Logistics Ltd - Board Minutes","June 2026","","Attendees: C. Anderson, P. Harris","Approved increased procurement budget for Q3.","Preliminary discussion of market expansion opportunities.") }
    @{ Share="Executive"; File="Board Minutes - July 2026.docx"; Type="docx"; Owner="c.anderson"; Month=7
       Paragraphs=@("Apex Global Logistics Ltd - Board Minutes","July 2026","","Attendees: C. Anderson, P. Harris","Expansion Strategy paper tabled for review.","Acquisition discussions to remain strictly confidential pending due diligence.") }
    @{ Share="Executive"; File="Expansion Strategy.docx"; Type="docx"; Owner="c.anderson"; Month=7; LateJuly=$true
       Paragraphs=@("Apex Global Logistics Ltd - CONFIDENTIAL","European Market Expansion Strategy","","Proposal to establish a regional distribution hub in the Netherlands by Q2 2027.","Estimated capital investment: GBP 2.4 million.","Competitive analysis identifies three regional logistics providers as primary rivals for contract wins.") }
    @{ Share="Executive"; File="Confidential Acquisition Plan.docx"; Type="docx"; Owner="p.harris"; Month=7; LateJuly=$true
       Paragraphs=@("Apex Global Logistics Ltd - STRICTLY CONFIDENTIAL","Draft Acquisition Plan","","Target: a regional logistics competitor operating in the Midlands corridor.","Indicative offer under review by the Board.","This document must not be shared outside Executive team members.") }
    @{ Share="Executive"; File="Confidential Budget.xlsx"; Type="xlsx"; Owner="p.harris"; Month=7; LateJuly=$true
       Rows=@(@("Line Item","2026 (GBP)","2027 Projected (GBP)"),@("Acquisition Reserve","1,800,000","Confidential"),@("Expansion Capital","2,400,000","Confidential"),@("Executive Contingency","350,000","Confidential")) }

    # --- Procurement ---
    @{ Share="Procurement"; File="Supplier List.xlsx"; Type="xlsx"; Owner="d.scott"; Month=5
       Rows=@(@("Supplier","Category","Contract End"),@("Meridian Packaging Ltd","Packaging","2027-03-01"),@("Northgate Fuel Services","Fuel","2026-12-31"),@("Castlebridge Parts Co","Vehicle Parts","2027-06-30")) }
    @{ Share="Procurement"; File="Purchase Orders - Q2 2026.xlsx"; Type="xlsx"; Owner="e.thomas"; Month=6
       Rows=@(@("PO Number","Supplier","Value (GBP)"),@("PO-2201","Meridian Packaging Ltd","14,200"),@("PO-2214","Northgate Fuel Services","38,500"),@("PO-2229","Castlebridge Parts Co","9,750")) }
    @{ Share="Procurement"; File="Tender Documents.docx"; Type="docx"; Owner="d.scott"; Month=6
       Paragraphs=@("Apex Global Logistics Ltd - Tender Documentation","","Tender reference: APX-T-2026-04","Scope: regional pallet supply contract","Closing date for submissions: 31 July 2026") }
    @{ Share="Procurement"; File="Stock Requests.xlsx"; Type="xlsx"; Owner="e.thomas"; Month=7
       Rows=@(@("Item","Requested By","Quantity"),@("Pallet Wrap (Roll)","Warehouse Team A","150"),@("Fuel Cards","Fleet Management","12"),@("Safety Gloves (Box)","Warehouse Team B","40")) }

    # --- Public ---
    @{ Share="Public"; File="Holiday Calendar.xlsx"; Type="xlsx"; Owner="it.central"; Month=5
       Rows=@(@("Holiday","Date"),@("Summer Bank Holiday","2026-08-31"),@("Christmas Day","2026-12-25"),@("Boxing Day","2026-12-28")) }
    @{ Share="Public"; File="Phone Directory.docx"; Type="docx"; Owner="it.central"; Month=5
       Paragraphs=@("Apex Global Logistics Ltd - Internal Phone Directory","","IT Helpdesk: ext. 100","Operations: ext. 200","Finance: ext. 300","HR: ext. 400") }
    @{ Share="Public"; File="Health and Safety.pdf"; Type="pdf"; Owner="it.central"; Month=5
       Lines=@("Apex Global Logistics Ltd","Health and Safety Guidance","","All warehouse staff must wear high-visibility clothing.","Report all incidents to your line manager within 24 hours.","Fire assembly point: main car park, Zone B.") }
    @{ Share="Public"; File="Staff Notice.txt"; Type="txt"; Owner="it.central"; Month=7; LateJuly=$true
       Lines=@("Staff Notice - 28 July 2026","","Reminder: the staff car park resurfacing begins 3 August 2026.","Please use the overflow car park on Elm Road during this period.") }
)

# ---------------------------------------------------------------
# 4. GENERATE FILES
# ---------------------------------------------------------------

Write-Host "`n[2/4] Verifying departmental share folders exist..." -ForegroundColor Yellow
$UniqueShares = $Manifest.Share | Select-Object -Unique
foreach ($ShareName in $UniqueShares) {
    $FolderPath = Join-Path $SharesRoot $ShareName
    if (-not (Test-Path $FolderPath)) {
        Write-Warning "  Share folder missing: $FolderPath -- has Script 01 been run? Creating folder now."
        New-Item -Path $FolderPath -ItemType Directory | Out-Null
    }
}

Write-Host "`n[3/4] Generating documents..." -ForegroundColor Yellow

foreach ($Item in $Manifest) {
    $FolderPath = Join-Path $SharesRoot $Item.Share
    $FilePath = Join-Path $FolderPath $Item.File
    $OwnerName = $OwnerNames[$Item.Owner]

    # Resolve the backdated timestamp for this file
    if ($Item.LateJuly) {
        $FileDate = Get-RandomDateInMonth -Year 2026 -Month $Item.Month -FromDay 20 -ToDay 31
    } else {
        $FileDate = Get-RandomDateInMonth -Year 2026 -Month $Item.Month
    }

    try {
        switch ($Item.Type) {
            "docx" { New-MinimalDocx -Path $FilePath -Paragraphs $Item.Paragraphs -Owner $OwnerName -Created $FileDate }
            "xlsx" { New-MinimalXlsx -Path $FilePath -SheetName "Sheet1" -Rows $Item.Rows -Owner $OwnerName -Created $FileDate }
            "pdf"  { New-SimplePdf -Path $FilePath -Lines $Item.Lines -Title $Item.File }
            "txt"  { Set-Content -Path $FilePath -Value ($Item.Lines -join "`r`n") -Encoding UTF8 }
        }

        Set-BackdatedTimestamp -Path $FilePath -Date $FileDate
        if ($Item.Owner -ne "it.central") {
            Set-FileOwnerBestEffort -Path $FilePath -SamAccountName $Item.Owner
        }

        $targetFlag = if ($Item.LateJuly -and ($Item.Share -in @("Operations","Executive")) -and ($Item.File -in @("Delivery Schedule.xlsx","Expansion Strategy.docx","Confidential Acquisition Plan.docx","Confidential Budget.xlsx"))) { " [SCRIPT 03 TARGET]" } else { "" }
        Write-Host "  Created: $($Item.Share)\$($Item.File) (owner: $($Item.Owner), dated $($FileDate.ToString('yyyy-MM-dd')))$targetFlag"
        $FilesCreated++
    } catch {
        Write-Warning "  Failed to create $($Item.Share)\$($Item.File): $($_.Exception.Message)"
        $ErrorsEncountered++
    }
}

# ---------------------------------------------------------------
# 5. SUMMARY
# ---------------------------------------------------------------

$Finish = Get-Date
$Duration = $Finish - $Start

Write-Host "`n[4/4] Build summary" -ForegroundColor Yellow
Write-Host "  Files created:       $FilesCreated / $($Manifest.Count)"
Write-Host "  Errors encountered:  $ErrorsEncountered"
Write-Host "  Execution time:      $($Duration.ToString())"
Write-Host "  Script 03 targets:   Delivery Schedule.xlsx, Expansion Strategy.docx, Confidential Acquisition Plan.docx, Confidential Budget.xlsx"

Write-Host "`n=== Enterprise population complete ===" -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Spot-check a few files open correctly in Word/Excel/a PDF reader on APEX-WS01"
Write-Host "  2. Confirm file timestamps with: Get-ChildItem C:\Shares -Recurse | Select FullName,CreationTime,LastWriteTime"
Write-Host "  3. Take a VirtualBox snapshot: 'Post-Enterprise-Population'"
Write-Host "  4. Proceed to Script 03: Insider Activity Simulation"
Write-Host "`nFull execution log saved to: $LogPath" -ForegroundColor Cyan

Stop-Transcript
