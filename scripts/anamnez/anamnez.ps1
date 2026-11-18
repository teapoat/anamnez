# Anamnez collector: event logs, BSOD dumps, WER reports, setup/driver logs and a text snapshot of
# hardware, drivers, software, disks, power, network, printers, security.
# Result, one copy: <stick>:\evt\<date_time>_<HOST>.7z, or C:\Install\evt\... when run from C: or the
# stick has under 1 GB free. Without 7-Zip the result is the unpacked folder of the same name.
# Works in C:\Install\evt, except when C: has under 1 GB free: then directly on the stick.
# Run from the stick via anamnez.bat (elevates itself). Targets PowerShell 2.0 (Win7) .. 5.1:
# every step is optional - a failed step goes to 00-journal.txt and the run goes on.
# The portable package includes a runtime for Win7 and one for Win10/11.
# External tools are found recursively under tools\: smartctl.exe, autorunsc64.exe or autorunsc.exe,
# and 7zr.exe, 7za.exe or 7z.exe. Missing tools skip their collection steps.
# Script text is ASCII on purpose: Windows PowerShell reads a BOM-less .ps1 in the ANSI code page.

param([switch]$FromMenu, [switch]$DiskSnapshot)

$wmiJunk = '__*', 'Scope', 'Path', 'Options', 'ClassPath', 'Properties', 'SystemProperties', 'Qualifiers', 'Site', 'Container'
function Show-Wmi($class, $ns = 'root\cimv2', $filter, [switch]$VolumeSummary) {
    $p = @{ Class = $class; Namespace = $ns; ErrorAction = 'Stop' }
    if ($filter) { $p.Filter = $filter }
    '===== {0} =====' -f $class
    try {
        $inst = @(Get-WmiObject @p)
        # An empty WMI class and a failed query convey different things.
        if ($inst.Count -eq 0) { '  (no instances)' }
        else { $inst | Select-Object -Property * -ExcludeProperty $wmiJunk | Format-List | Out-String -Width 300 }
        if ($VolumeSummary) {
            foreach ($d in @($inst | Where-Object { $_.DriveType -eq 3 })) {
                'Volume       : {0} {1:N1} of {2:N1} GB free' -f $d.DeviceID, ($d.FreeSpace / 1GB), ($d.Size / 1GB)
            }
        }
    } catch { '  n/a: {0}' -f $_ }
}
function Has-Cmd($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }

function Show-DiskVolumes([version]$osVersion) {
    if ($osVersion -ge [version]'6.2') {
        Show-Wmi 'Win32_Volume'
        Show-Wmi 'Win32_LogicalDisk' -VolumeSummary
        return
    }
    # Both WMI volume classes have stalled on Win7. Query fixed local drives directly.
    '===== Local volumes (DriveInfo) ====='
    foreach ($drive in [IO.DriveInfo]::GetDrives()) {
        try {
            if ($drive.DriveType -ne [IO.DriveType]::Fixed) { continue }
            $name = $drive.Name.TrimEnd('\')
            $free = $drive.AvailableFreeSpace
            $size = $drive.TotalSize
            'Volume       : {0} {1:N1} of {2:N1} GB free' -f $name, ($free / 1GB), ($size / 1GB)
            '  File system: {0}' -f $drive.DriveFormat
        } catch { '  n/a: {0}: {1}' -f $drive.Name, $_ }
    }
}

if ($DiskSnapshot) {
    [Console]::OutputEncoding = [Text.Encoding]::UTF8
    foreach ($c in 'Win32_DiskDrive', 'Win32_DiskPartition') { Show-Wmi $c }
    Show-Wmi 'MSStorageDriver_FailurePredictStatus' 'root\wmi'
    '===== MSStorageDriver_FailurePredictData (raw SMART attribute table, hex) ====='
    try {
        Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictData -ErrorAction Stop | ForEach-Object {
            $_.InstanceName
            ($_.VendorSpecific | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
        }
    } catch { '  n/a: {0}' -f $_ }
    if (Has-Cmd 'Get-PhysicalDisk') {
        '===== Get-Disk ====='; Get-Disk | Format-List * | Out-String -Width 300
        '===== Get-Partition ====='; Get-Partition | Format-List * | Out-String -Width 300
        '===== Get-PhysicalDisk ====='; Get-PhysicalDisk | Format-List * | Out-String -Width 300
        '===== Get-StorageReliabilityCounter ====='; Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List * | Out-String -Width 300
    }
    Show-DiskVolumes ([Environment]::OSVersion.Version)
    exit 0
}

$self = $MyInvocation.MyCommand.Path
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        # On Win7 / PowerShell 2.0 the launch can succeed while waiting fails.
        Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$self`"" -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host 'Could not start Anamnez as administrator.' -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        [void](Read-Host 'Press Enter to continue')
        exit 1
    }
    if ($FromMenu) {
        Write-Host 'Anamnez is running in a separate window.'
        [void](Read-Host 'After Anamnez closes, press Enter to return to the menu')
    }
    exit 0
}

# Size limits: FAT32 stick cannot hold a file over 4 GB, and a full MEMORY.DMP can be tens of GB
$maxMemoryDmp = 1GB     # C:\Windows\MEMORY.DMP - copied only if not larger
$maxLiveDmp   = 300MB   # C:\Windows\LiveKernelReports\*.dmp - per file
$maxTextLog   = 100MB   # setupapi.dev.log and Panther logs
$maxCbsLog    = 100000000
$maxWer       = 500     # newest Report.wer files to take

$scriptDir = Split-Path -Parent $self
$stick = [IO.Path]::GetPathRoot($self)
$name  = '{0}_{1}' -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'), $env:COMPUTERNAME

# A reset hardware clock can distort timestamps and incident counts. Flag implausible years
# and clocks that lag behind the script's last write time.
$clockWarn = $null
$nowLocal = Get-Date
$selfStamp = $null
try { $selfStamp = (Get-Item $self).LastWriteTime } catch {}
if ($nowLocal.Year -lt 2005) {
    $clockWarn = 'machine clock reads {0:yyyy-MM-dd HH:mm} - CLOCK IS WRONG (dead CMOS cell?)' -f $nowLocal
} elseif ($selfStamp -ne $null -and $nowLocal -lt $selfStamp.AddDays(-1)) {
    $clockWarn = 'machine clock reads {0:yyyy-MM-dd HH:mm}, behind this script file ({1:yyyy-MM-dd}) - CLOCK IS WRONG' -f $nowLocal, $selfStamp
}

# Prefer the system drive for staging. If it has less than 1 GB free and the launch drive
# has enough space, write directly to the launch drive.
function Free-Bytes($drive) {
    try {
        $info = New-Object IO.DriveInfo -ArgumentList $drive -ErrorAction Stop
        return [double]$info.AvailableFreeSpace
    } catch { return $null }
}
$sysDrive = $env:SystemDrive + '\'
$sysFree = Free-Bytes $sysDrive
$stickFree = $null
$workOnStick = $false
if ($stick -ne $sysDrive -and $sysFree -ne $null -and $sysFree -lt 1GB) {
    $stickFree = Free-Bytes $stick
    if ($stickFree -eq $null -or $stickFree -ge 1GB) { $workOnStick = $true }
}
if ($workOnStick) { $root = Join-Path (Join-Path $stick 'evt') $name }
else { $root = Join-Path 'C:\Install\evt' $name }
# Scratch for tool output nobody keeps (7-Zip etc.): %TEMP% is on C:, useless when C: is full
if ($workOnStick) { $tmpDir = Join-Path $stick 'evt' } else { $tmpDir = $env:TEMP }
foreach ($d in 'evt', 'dumps', 'wer', 'files', 'info') {
    New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null
}
$journal = Join-Path $root '00-journal.txt'
$fails = New-Object System.Collections.ArrayList

function Say($msg, $color = 'Gray') {
    $line = '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $journal -Value $line -Encoding UTF8
}
function Fail($msg) { [void]$fails.Add($msg); Say ('FAIL ' + $msg) 'Yellow' }

function Copy-CbsLog($source, $destination, [long]$limit) {
    # Read a bounded byte snapshot while the servicing process may still be writing.
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $inputStream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    $staged = $destination + '.' + [guid]::NewGuid() + '.tmp'
    try {
        $length = $inputStream.Length
        $remaining = [Math]::Min($length, $limit)
        $inputStream.Position = $length - $remaining
        $outputStream = [IO.File]::Open($staged, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try {
            $buffer = New-Object byte[] 262144
            while ($remaining -gt 0) {
                $chunkSize = [int][Math]::Min([long]$buffer.Length, $remaining)
                $read = $inputStream.Read($buffer, 0, $chunkSize)
                if ($read -eq 0) { throw 'CBS.log was shortened while being read' }
                $outputStream.Write($buffer, 0, $read)
                $remaining -= $read
            }
        } finally { $outputStream.Dispose() }
        [IO.File]::Move($staged, $destination)
        return $length
    } finally {
        $inputStream.Dispose()
        if (Test-Path -LiteralPath $staged) {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($clockWarn) {
    Say $clockWarn 'Yellow'
    Say '   every timestamp below, and in the event logs, is off by the same amount - do not date anything by them' 'Yellow'
}

# Native tool with timeout. Output is kept raw (console tools write in the OEM code page, cp866 on RU).
# Empty $outName = output not needed (tool writes its own file).
function Run-Exe($file, $argLine, $outName, [int]$timeoutSec = 120) {
    if ($outName) { $out = Join-Path $root ('info\' + $outName) } else { $out = Join-Path $tmpDir ('anamnez-' + [guid]::NewGuid() + '.txt') }
    $err = $out + '.err'
    $sp = @{ FilePath = $file; RedirectStandardOutput = $out; RedirectStandardError = $err; NoNewWindow = $true; PassThru = $true }
    if ($argLine) { $sp.ArgumentList = $argLine }
    $script:exeExit = $null
    try {
        $p = Start-Process @sp -ErrorAction Stop
        $null = $p.Handle   # without touching Handle, ExitCode of a -PassThru process can come back empty
        if (-not $p.WaitForExit($timeoutSec * 1000)) {
            try { $p.Kill(); [void]$p.WaitForExit(2000) } catch {}
            Fail ('{0} {1}: timeout {2}s, killed' -f $file, $argLine, $timeoutSec)
        } else { $script:exeExit = $p.ExitCode }
    } catch { Fail ('{0} {1}: {2}' -f $file, $argLine, $_) }
    if ((Test-Path $err) -and (Get-Item $err).Length -eq 0) { Remove-Item $err -Force }
    # Tool refused (bad args etc.): empty output + stderr - count as failed, not silently empty
    elseif ($outName -and (Test-Path $err) -and -not ((Test-Path $out) -and (Get-Item $out).Length -gt 0)) {
        Fail ('{0} {1}: no output, see {2}' -f $file, $argLine, (Split-Path $err -Leaf))
    }
    if (-not $outName) { Remove-Item $out, $err -Force -ErrorAction SilentlyContinue }
    # Normalize captured console output to UTF-8.
    elseif ((Test-Path $out) -and (Get-Item $out).Length -gt 0) { Convert-Oem $outName }
}

# PowerShell/WMI step in this process. Text goes out as UTF-8.
function Run-Ps($outName, [scriptblock]$sb) {
    $out = Join-Path $root ('info\' + $outName)
    try { & $sb 2>&1 | Out-File -FilePath $out -Encoding UTF8 -Width 400 }
    catch { Fail ('{0}: {1}' -f $outName, $_) }
}

# Same, in a background job with timeout - for queries that can hang (spooler, Defender, reliability).
# The scriptblock must be self-contained and return text.
function Run-PsJob($outName, [scriptblock]$sb, [int]$timeoutSec = 90) {
    $out = Join-Path $root ('info\' + $outName)
    try {
        $job = Start-Job -ScriptBlock $sb
        if (Wait-Job $job -Timeout $timeoutSec) {
            Receive-Job $job 2>&1 | Out-File -FilePath $out -Encoding UTF8 -Width 400
        } else {
            Stop-Job $job
            Fail ('{0}: timeout {1}s' -f $outName, $timeoutSec)
        }
        Remove-Job $job -Force
    } catch { Fail ('{0}: {1}' -f $outName, $_) }
}

# Registry value or $null when the key/value is absent (absent and 0 mean different things here).
function Reg-Val($key, $valName) {
    try { $p = Get-ItemProperty -Path $key -Name $valName -ErrorAction Stop; return $p.$valName } catch { return $null }
}
function Show-Val($v) { if ($null -eq $v) { return '(not set)' } return [string]$v }

# Console tools write in the system OEM code page (cp866 on RU) - rewrite such a file as UTF-8 with BOM.
# The OEM page is the system one (Nls\CodePage\OEMCP), not the user culture.
function Convert-Oem($outName) {
    $p = Join-Path $root ('info\' + $outName)
    if (-not (Test-Path $p)) { return }
    try {
        $bytes = [IO.File]::ReadAllBytes($p)
        if ($bytes.Length -eq 0) { return }
        # Some tools, including Autorunsc, write UTF-16 with a BOM.
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $text = [Text.Encoding]::Unicode.GetString($bytes)
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $text = [Text.Encoding]::BigEndianUnicode.GetString($bytes)
        } else {
            # Some tools write UTF-8. Fall back to the system OEM code page only if UTF-8 decoding fails.
            try { $text = (New-Object Text.UTF8Encoding $false, $true).GetString($bytes) }
            catch {
                $cp = Reg-Val 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' 'OEMCP'
                if ($cp) { $enc = [Text.Encoding]::GetEncoding([int]$cp) } else { $enc = [Console]::OutputEncoding }
                $text = $enc.GetString($bytes)
            }
        }
        [IO.File]::WriteAllText($p, $text.TrimStart([char]0xFEFF), (New-Object Text.UTF8Encoding $true))
    } catch { Fail ('{0}: OEM to UTF-8: {1}' -f $outName, $_) }
}

# Optional tool: first of $names found anywhere under tools\ that can run on this OS.
# Tools come as whole unpacked distributions (tools\7zip\7z.exe, tools\smartmontools\bin\smartctl.exe).
$toolsDir = Join-Path $scriptDir 'tools'
$os64 = [IntPtr]::Size -eq 8 -or $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64'
function Test-Exe64($path) {
    # PE header: offset of 'PE\0\0' at 0x3C, machine type right after it; 0x8664 = x64
    try {
        $fs = [IO.File]::OpenRead($path)
        try {
            $b = New-Object byte[] 4096; [void]$fs.Read($b, 0, 4096)
            $pe = [BitConverter]::ToInt32($b, 0x3C)
            return ([BitConverter]::ToUInt16($b, $pe + 4) -eq 0x8664)
        } finally { $fs.Close() }
    } catch { return $false }
}
function Find-Tool([string[]]$names) {
    if (-not (Test-Path $toolsDir)) { return $null }
    foreach ($n in $names) {
        foreach ($f in @(Get-ChildItem $toolsDir -Recurse -Filter $n -ErrorAction SilentlyContinue)) {
            if ($f.PSIsContainer) { continue }
            if (-not $os64 -and (Test-Exe64 $f.FullName)) { Say ('   {0}: x64 build, this Windows is 32-bit - skipped' -f $f.FullName) 'DarkGray'; continue }
            return $f.FullName
        }
    }
    return $null
}

Say ('anamnez -> {0}' -f $root) 'Cyan'
if ($stick -eq ($env:SystemDrive + '\')) { Say 'Script runs from the system drive, not from a stick: result stays in C:\Install\evt' 'Yellow' }
if ($sysFree -ne $null) { Say ('   system drive {0} free: {1:N0} MB' -f $sysDrive, ($sysFree / 1MB)) }
if ($workOnStick) { Say ('   system drive has under 1 GB free - working directly on the stick {0}' -f $stick) 'Yellow' }
elseif ($sysFree -ne $null -and $sysFree -lt 1GB) {
    Say '   system drive has under 1 GB free and no stick with 1 GB free - steps may fail for lack of space' 'Yellow'
}

# ---------- 1. Event logs ----------
Say '1/6 Event logs'
$channels = @(
    'System', 'Application', 'Security', 'Setup', 'HardwareEvents',
    'Microsoft-Windows-Kernel-PnP/Configuration',
    'Microsoft-Windows-Kernel-Power/Thermal-Operational',
    'Microsoft-Windows-Kernel-Boot/Operational',
    'Microsoft-Windows-Kernel-WHEA/Errors',
    'Microsoft-Windows-Kernel-WHEA/Operational',
    'Microsoft-Windows-Diagnostics-Performance/Operational',
    'Microsoft-Windows-Resource-Exhaustion-Detector/Operational',
    'Microsoft-Windows-Storage-Storport/Operational',
    'Microsoft-Windows-Storage-ClassPnP/Operational',
    'Microsoft-Windows-Ntfs/Operational',
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
    'Microsoft-Windows-UserPnp/DeviceInstall',
    'Microsoft-Windows-DeviceSetupManager/Admin',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-Audio/Operational',
    'Microsoft-Windows-PrintService/Admin',
    'Microsoft-Windows-PrintService/Operational',
    'Microsoft-Windows-SMBClient/Operational',
    'Microsoft-Windows-SMBClient/Connectivity',
    'Microsoft-Windows-SMBServer/Operational',
    'Microsoft-Windows-SMBServer/Security',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-WLAN-AutoConfig/Operational'
)
$evtStat = New-Object System.Collections.ArrayList
foreach ($ch in $channels) {
    $file = Join-Path $root ('evt\' + ($ch -replace '[\\/ ]', '_') + '.evtx')
    $o = & wevtutil.exe epl $ch $file 2>&1
    if ($LASTEXITCODE -eq 15007) { continue }   # channel does not exist on this Windows version
    if ($LASTEXITCODE -ne 0) { Fail ('wevtutil epl {0}: {1} {2}' -f $ch, $LASTEXITCODE, ($o -join ' ')); continue }
    $n = '?'
    $gli = & wevtutil.exe gli $file /lf:true 2>&1
    foreach ($l in $gli) { if ("$l" -match 'numberOfLogRecords:\s*(\d+)') { $n = $matches[1] } }
    [void]$evtStat.Add(('{0,8}  {1}' -f $n, $ch))
}
Say ('   exported {0} logs' -f $evtStat.Count)

# ---------- 2. Dumps ----------
Say '2/6 Crash dumps'
$dumpList = New-Object System.Collections.ArrayList
$mini = Join-Path $env:SystemRoot 'Minidump'
if (Test-Path $mini) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'dumps\Minidump') | Out-Null
    foreach ($f in @(Get-ChildItem $mini -Filter *.dmp -ErrorAction SilentlyContinue)) {
        try { Copy-Item $f.FullName (Join-Path $root 'dumps\Minidump') -ErrorAction Stop; [void]$dumpList.Add(('copied   {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName)) }
        catch { Fail ('copy {0}: {1}' -f $f.FullName, $_) }
    }
}
$mem = Join-Path $env:SystemRoot 'MEMORY.DMP'
if (Test-Path $mem) {
    $f = Get-Item $mem
    if ($f.Length -le $maxMemoryDmp) {
        try { Copy-Item $f.FullName (Join-Path $root 'dumps') -ErrorAction Stop; [void]$dumpList.Add(('copied   {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName)) }
        catch { Fail ('copy {0}: {1}' -f $f.FullName, $_) }
    } else { [void]$dumpList.Add(('TOO BIG  {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName)) }
}
$lkr = Join-Path $env:SystemRoot 'LiveKernelReports'
if (Test-Path $lkr) {
    foreach ($f in @(Get-ChildItem $lkr -Recurse -Filter *.dmp -ErrorAction SilentlyContinue)) {
        if ($f.Length -le $maxLiveDmp) {
            $to = Join-Path $root ('dumps\LiveKernelReports\' + $f.Directory.Name)
            New-Item -ItemType Directory -Force -Path $to | Out-Null
            try { Copy-Item $f.FullName $to -ErrorAction Stop; [void]$dumpList.Add(('copied   {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName)) }
            catch { Fail ('copy {0}: {1}' -f $f.FullName, $_) }
        } else { [void]$dumpList.Add(('TOO BIG  {0,12:N0}  {1:yyyy-MM-dd HH:mm}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName)) }
    }
}
# Header says WHERE we looked, so an empty list is distinguishable from "did not look"
$dumpChecked = @()
foreach ($d in @($mini, $lkr)) {
    if (Test-Path $d) {
        $n = @(Get-ChildItem $d -Recurse -Filter *.dmp -ErrorAction SilentlyContinue).Count
        $dumpChecked += 'checked  {0}: {1} .dmp' -f $d, $n
    } else { $dumpChecked += 'checked  {0}: folder absent' -f $d }
}
if (Test-Path $mem) { $dumpChecked += 'checked  {0}: present' -f $mem } else { $dumpChecked += 'checked  {0}: absent' -f $mem }
$dumpChecked += '(crash dump and WER settings - crash-settings.txt)'
$dumpChecked += ''
@($dumpChecked) + @($dumpList) | Out-File (Join-Path $root 'info\dumps-list.txt') -Encoding UTF8
Say ('   dumps found: {0}' -f $dumpList.Count)

# ---------- 3. WER reports (application crashes, LiveKernelEvent) ----------
Say '3/6 WER reports'
$werDirs = 'ReportArchive', 'ReportQueue' | ForEach-Object { Join-Path $env:ProgramData ('Microsoft\Windows\WER\' + $_) } | Where-Object { Test-Path $_ }
$wer = @()
if ($werDirs) { $wer = @(Get-ChildItem $werDirs -Recurse -Filter Report.wer -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $maxWer) }
foreach ($f in $wer) {
    try { Copy-Item $f.FullName (Join-Path $root ('wer\' + $f.Directory.Name + '.wer')) -ErrorAction Stop }
    catch { Fail ('copy {0}: {1}' -f $f.FullName, $_) }
}
Say ('   Report.wer: {0}' -f $wer.Count)

# Save the recording settings so empty dump and WER folders can be interpreted.
$cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$cde = Reg-Val $cc 'CrashDumpEnabled'
$dumpModes = @{ 0 = 'NONE - kernel dumps are NOT written'; 1 = 'complete'; 2 = 'kernel'; 3 = 'small (minidump)'; 7 = 'automatic' }
if ($null -eq $cde) { $dumpMode = '(not set)' }
elseif ($dumpModes.ContainsKey([int]$cde)) { $dumpMode = '{0} = {1}' -f $cde, $dumpModes[[int]$cde] }
else { $dumpMode = '{0} = unknown' -f $cde }
$werKeys = @(
    @('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting', 'Disabled', 1),
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting', 'Disabled', 1),
    @('HKCU:\Software\Microsoft\Windows\Windows Error Reporting', 'Disabled', 1),
    @('HKCU:\Software\Policies\Microsoft\Windows\Windows Error Reporting', 'Disabled', 1),
    @('HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting', 'DoReport', 0)
)
$werOff = @()
$werLines = @()
foreach ($k in $werKeys) {
    $v = Reg-Val $k[0] $k[1]
    $werLines += '  {0} \ {1} = {2}' -f $k[0], $k[1], (Show-Val $v)
    if ($null -ne $v -and [int]$v -eq $k[2]) { $werOff += '{0}\{1}={2}' -f $k[0], $k[1], $v }
}
$werSvc = Get-WmiObject Win32_Service -Filter "Name='WerSvc'" -ErrorAction SilentlyContinue
if ($werOff.Count) { $werState = 'OFF by ' + ($werOff -join '; ') }
elseif (-not $werSvc) { $werState = 'service WerSvc absent' }
elseif ($werSvc.StartMode -eq 'Disabled') { $werState = 'OFF - service WerSvc disabled' }
else { $werState = 'on (no disabling setting found)' }
Run-Ps 'crash-settings.txt' {
    '===== Kernel crash dumps (CrashControl) ====='
    'Mode (CrashDumpEnabled) : {0}' -f $dumpMode
    foreach ($n in 'AutoReboot', 'MinidumpDir', 'DumpFile', 'AlwaysKeepMemoryDump', 'DedicatedDumpFile', 'Overwrite') {
        '{0,-24}: {1}' -f $n, (Show-Val (Reg-Val $cc $n))
    }
    ''
    '===== Page file (a kernel dump is written through it unless DedicatedDumpFile is set) ====='
    'AutomaticManagedPagefile: {0}' -f (Get-WmiObject Win32_ComputerSystem).AutomaticManagedPagefile
    $pf = @(Get-WmiObject Win32_PageFileUsage -ErrorAction SilentlyContinue)
    if ($pf.Count) { foreach ($f in $pf) { '{0}  {1} MB allocated, peak {2} MB' -f $f.Name, $f.AllocatedBaseSize, $f.PeakUsage } }
    else { 'NO PAGE FILE in use - kernel dumps may not be written' }
    ''
    '===== Windows Error Reporting ====='
    'WER state               : {0}' -f $werState
    if ($werSvc) { 'Service WerSvc          : {0}, start {1}' -f $werSvc.State, $werSvc.StartMode } else { 'Service WerSvc          : absent' }
    $werLines
    ''
    '===== User-mode crash dumps (LocalDumps) ====='
    # Usually absent; reg.exe on a missing key only adds a red NativeCommandError to the file
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps') {
        reg.exe query 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' /s 2>&1
    } else { '(not set - user-mode dumps are not kept)' }
}
Say ('   crash dumps: {0}; WER: {1}' -f $dumpMode, $werState)

# ---------- 4. Text logs from disk ----------
Say '4/6 Setup / driver install / CBS logs'
$textLogs = @(
    (Join-Path $env:SystemRoot 'INF\setupapi.dev.log'),
    (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'),
    (Join-Path $env:SystemRoot 'Panther\setupact.log'),
    (Join-Path $env:SystemRoot 'Panther\setuperr.log'),
    ($env:SystemDrive + '\$WINDOWS.~BT\Sources\Panther\setupact.log'),
    ($env:SystemDrive + '\$WINDOWS.~BT\Sources\Panther\setuperr.log')
)
foreach ($p in $textLogs) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $f = Get-Item -LiteralPath $p -Force
    if ($f.Name -ne 'CBS.log' -and $f.Length -gt $maxTextLog) {
        Say ('   skipped (too big {0:N0}): {1}' -f $f.Length, $p) 'Yellow'
        continue
    }
    $to = Join-Path $root ('files\' + ($f.Directory.FullName.Substring(3) -replace '[\\$~ ]', '_') + '__' + $f.Name)
    try {
        if ($f.Name -eq 'CBS.log') {
            $originalBytes = Copy-CbsLog $p $to $maxCbsLog
            if ($originalBytes -gt $maxCbsLog) {
                Say ('   CBS.log: saved the last {0} of {1} bytes (partial log)' -f $maxCbsLog, $originalBytes) 'Yellow'
            }
        } else {
            Copy-Item -LiteralPath $p $to -ErrorAction Stop
        }
    } catch { Fail ('copy {0}: {1}' -f $p, $_) }
}

# ---------- 5. Snapshot ----------
Say '5/6 System snapshot (takes 1-5 min)'
Run-Exe 'systeminfo.exe' '' 'systeminfo.txt' 180   # The default list format works across Windows versions.
Run-Ps 'hardware.txt' {
    foreach ($c in 'Win32_OperatingSystem', 'Win32_ComputerSystem', 'Win32_BIOS', 'Win32_BaseBoard', 'Win32_Processor',
                   'Win32_PhysicalMemory', 'Win32_VideoController', 'Win32_SoundDevice', 'Win32_Battery') { Show-Wmi $c }
}
Run-Exe 'reg.exe' 'query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0"' 'cpu-microcode.txt'
Run-Ps 'devices-problem.txt' {
    Get-WmiObject Win32_PnPEntity -Filter 'ConfigManagerErrorCode<>0' |
        Select-Object Name, ConfigManagerErrorCode, Status, Service, DeviceID | Format-List | Out-String -Width 300
}
Run-Ps 'devices-all.csv' {
    Get-WmiObject Win32_PnPEntity | Select-Object Name, PNPClass, Manufacturer, Service, Status, ConfigManagerErrorCode, DeviceID |
        Sort-Object PNPClass, Name | ConvertTo-Csv -NoTypeInformation
}
Run-Ps 'drivers-pnp.csv' {
    Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceClass, DeviceName, DriverProviderName, DriverVersion, DriverDate, InfName, IsSigned, DeviceID |
        Sort-Object DeviceClass, DeviceName | ConvertTo-Csv -NoTypeInformation
}
Run-Exe 'driverquery.exe' '/V /FO CSV' 'driverquery.csv'
Run-Ps 'software.csv' {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName | ConvertTo-Csv -NoTypeInformation
}
Run-Ps 'hotfixes.csv' {
    Get-WmiObject Win32_QuickFixEngineering | Select-Object HotFixID, Description, InstalledOn, InstalledBy | ConvertTo-Csv -NoTypeInformation
}
Run-Ps 'services.csv' {
    Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName |
        Sort-Object Name | ConvertTo-Csv -NoTypeInformation
}
Run-Ps 'processes.csv' {
    Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, WorkingSetSize, CreationDate, ExecutablePath, CommandLine |
        ConvertTo-Csv -NoTypeInformation
}
Run-Ps 'startup.csv' {
    Get-WmiObject Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Csv -NoTypeInformation
}
Run-Exe 'schtasks.exe' '/query /fo csv /v' 'tasks.csv'
Run-Ps 'users.txt' {
    Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' |
        Select-Object Name, Disabled, Lockout, PasswordRequired, PasswordExpires, SID | Format-Table -AutoSize | Out-String -Width 300
}
Say '   Disk snapshot (up to 45s)'
Run-Exe 'powershell.exe' ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -DiskSnapshot' -f $self) 'disks.txt' 45
$smart = Find-Tool 'smartctl.exe'
if ($smart) {
    Say '   smartctl: scanning drives'
    Run-Exe $smart '--scan-open' 'smart-scan.txt'
    $scan = Join-Path $root 'info\smart-scan.txt'
    if (Test-Path $scan) {
        foreach ($l in (Get-Content $scan)) {
            $dev = ($l -split '#')[0].Trim()
            if ($dev -notlike '/dev/*') { continue }
            # Request extended SMART data because the legacy error log uses 28-bit addresses.
            Run-Exe $smart ('-x ' + $dev) ('smart-' + ((($dev -split '\s+')[0]) -replace '^/dev/', '') + '.txt') 120
        }
    }
} else { Say '   smartctl.exe not found under tools\ - SMART only via WMI' 'DarkGray' }
Run-Exe 'powercfg.exe' '/a' 'power-states.txt'
Run-Exe 'powercfg.exe' '/lastwake' 'power-lastwake.txt'
Run-Exe 'powercfg.exe' '/devicequery wake_armed' 'power-wake-armed.txt'
Run-Exe 'powercfg.exe' '/q' 'power-scheme.txt'
Run-Exe 'powercfg.exe' ('/batteryreport /output "{0}"' -f (Join-Path $root 'info\battery-report.html')) '' 60
Run-Exe 'bcdedit.exe' '/enum all' 'bcdedit.txt'
Run-Ps 'secureboot-tpm.txt' {
    '===== Confirm-SecureBootUEFI ====='
    if (Has-Cmd 'Confirm-SecureBootUEFI') { try { Confirm-SecureBootUEFI -ErrorAction Stop } catch { '  {0}' -f $_ } } else { '  n/a (Win7)' }
    Show-Wmi 'Win32_Tpm' 'root\cimv2\security\microsofttpm'
    reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot' /s 2>&1
}
Run-Exe 'dxdiag.exe' ('/t "{0}"' -f (Join-Path $root 'info\dxdiag.txt')) '' 180
Run-Exe 'ipconfig.exe' '/all' 'net-ipconfig.txt'
Run-Exe 'route.exe' 'print' 'net-route.txt'
Run-Exe 'netstat.exe' '-ano' 'net-netstat.txt' 60
Run-Exe 'arp.exe' '-a' 'net-arp.txt'
Run-Exe 'net.exe' 'share' 'net-share.txt' 30
Run-Exe 'net.exe' 'use' 'net-use.txt' 30
$wlanSvc = Get-WmiObject Win32_Service -Filter "Name='WlanSvc'" -ErrorAction SilentlyContinue
if ($wlanSvc) {
    Run-Exe 'netsh.exe' 'wlan show interfaces' 'net-wlan.txt' 30
    # Driver version/date, radio types, supported modes
    Run-Exe 'netsh.exe' 'wlan show drivers' 'net-wlan-drivers.txt' 30
    # wlanreport (Windows 8+): HTML timeline of the last 3 days - every connect/disconnect with its reason.
    if ([Environment]::OSVersion.Version -ge (New-Object Version 6, 2)) {
        $t0 = (Get-Date).AddMinutes(-1)
        Run-Exe 'netsh.exe' 'wlan show wlanreport' 'net-wlanreport-log.txt' 180
        $wr = Join-Path $env:ProgramData 'Microsoft\Windows\WlanReport'
        $got = 0
        foreach ($f in @(Get-ChildItem $wr -Filter 'wlan-report-latest*' -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTime -lt $t0) { continue }                # stale report from an earlier run
            if ($f.Length -gt 30MB) { Say ('   wlanreport: skipped (too big {0:N0}): {1}' -f $f.Length, $f.Name) 'Yellow'; continue }
            try { Copy-Item $f.FullName (Join-Path $root 'info') -ErrorAction Stop; $got++ } catch { Fail ('copy {0}: {1}' -f $f.FullName, $_) }
        }
        # Not a Fail: a desktop with WlanSvc but no adapter legitimately has no report
        if (-not $got) { Say '   wlanreport: no fresh wlan-report-latest.* - see net-wlanreport-log.txt' 'Yellow' }
    } else { Say '   wlanreport: needs Windows 8+, skipped' 'DarkGray' }
} else { Say '   no WLAN service - Wi-Fi steps skipped' 'DarkGray' }
Run-Exe 'netsh.exe' 'advfirewall show allprofiles' 'net-firewall.txt' 30
# Render System event messages on the source machine, where the provider's message resources
# are available. Format only the newest record per provider and event ID.
Run-PsJob 'event-texts.txt' {
    try { Add-Type -AssemblyName System.Core -ErrorAction Stop } catch {}
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery 'System', ([System.Diagnostics.Eventing.Reader.PathType]::LogName)
    $q.ReverseDirection = $true
    $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader $q
    $seen = @{}; $order = New-Object System.Collections.ArrayList; $n = 0
    while ($n -lt 60000) {
        $e = $rd.ReadEvent()
        if ($null -eq $e) { break }
        $n++
        $k = '{0}|{1}' -f $e.ProviderName, $e.Id
        if ($seen.ContainsKey($k)) { $seen[$k].N++; $e.Dispose(); continue }
        $msg = ''
        try { $msg = $e.FormatDescription() } catch { $msg = '(no text: {0})' -f $_.Exception.Message }
        if (-not $msg) { $msg = '(no message template on this machine)' }
        $msg = ($msg -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
        $t = ''
        if ($e.TimeCreated) { $t = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
        $seen[$k] = New-Object PSObject -Property @{ Provider = $e.ProviderName; Id = $e.Id; Level = $e.Level; N = 1; Last = $t; Text = $msg }
        [void]$order.Add($k)
        $e.Dispose()
    }
    'System log: {0} records read (newest first), {1} distinct provider+id. Level: 1 critical, 2 error, 3 warning, 4 info.' -f $n, $order.Count
    'count  level  last (local time)    provider  id  ::  newest message'
    foreach ($k in $order) {
        $r = $seen[$k]
        '{0,5}  L{1}  {2}  {3} {4}  ::  {5}' -f $r.N, $r.Level, $r.Last, $r.Provider, $r.Id, $r.Text
    }
} 120
Run-PsJob 'printers.txt' {
    $j = '__*', 'Scope', 'Path', 'Options', 'ClassPath', 'Properties', 'SystemProperties', 'Qualifiers', 'Site', 'Container'
    foreach ($c in 'Win32_Printer', 'Win32_PrinterDriver', 'Win32_TCPIPPrinterPort') {
        '===== {0} =====' -f $c
        Get-WmiObject $c | Select-Object -Property * -ExcludeProperty $j | Format-List | Out-String -Width 300
    }
    if (Get-Command Get-Printer -ErrorAction SilentlyContinue) {
        '===== Get-Printer ====='; Get-Printer | Format-List * | Out-String -Width 300
        '===== Get-PrinterPort ====='; Get-PrinterPort | Format-List * | Out-String -Width 300
    }
    '===== Point and Print / RPC policy ====='
    reg.exe query 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' /s 2>&1
    reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Print' /v RpcAuthnLevelPrivacyEnabled 2>&1
} 90
Run-PsJob 'antivirus.txt' {
    '===== SecurityCenter2 AntiVirusProduct ====='
    Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, pathToSignedProductExe | Format-List | Out-String -Width 300
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        '===== Get-MpComputerStatus ====='; Get-MpComputerStatus | Format-List * | Out-String -Width 300
        '===== Get-MpThreatDetection ====='; Get-MpThreatDetection | Format-List * | Out-String -Width 300
    }
} 90
Run-PsJob 'reliability.csv' {
    Get-WmiObject Win32_ReliabilityRecords | Select-Object TimeGenerated, SourceName, ProductName, EventIdentifier, Message |
        ConvertTo-Csv -NoTypeInformation
} 240
$arc = Find-Tool 'autorunsc64.exe', 'autorunsc.exe'
if ($arc) {
    Say '   Autorunsc: collecting startup entries'
    Run-Exe $arc '-accepteula -a * -c -h -s -nobanner *' 'autoruns.csv' 600
}
else { Say '   autorunsc not found under tools\ - autostart only via WMI/schtasks' 'DarkGray' }

# ---------- Summary ----------
$os = Get-WmiObject Win32_OperatingSystem; $cs = Get-WmiObject Win32_ComputerSystem
$boot = $os.ConvertToDateTime($os.LastBootUpTime); $up = (Get-Date) - $boot
$tz = [TimeZoneInfo]::Local
$fw = 'Legacy BIOS'; if ((& bcdedit.exe /enum '{current}' 2>&1) -match 'winload\.efi') { $fw = 'UEFI' }
$sum = @()
$sum += 'anamnez.ps1 - collected {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
if ($clockWarn) {
    $sum += '!! CLOCK      : {0}' -f $clockWarn
    $sum += '!!              dates in this dump and in the event logs are NOT trustworthy'
}
$sum += 'Host         : {0}   user: {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME
$sum += 'Time zone    : {0}, offset now {1} (evtx/WER keep UTC)' -f $tz.DisplayName, $tz.GetUtcOffset((Get-Date))
$sum += 'OS           : {0} {1} build {2} {3}, installed {4:yyyy-MM-dd}' -f $os.Caption, $os.CSDVersion, $os.BuildNumber, $os.OSArchitecture, $os.ConvertToDateTime($os.InstallDate)
$sum += 'Last boot    : {0:yyyy-MM-dd HH:mm}  (uptime {1}d {2}h {3}m)' -f $boot, $up.Days, $up.Hours, $up.Minutes
$sum += 'Firmware     : {0}' -f $fw
$sum += 'Machine      : {0} {1}' -f $cs.Manufacturer, $cs.Model
foreach ($b in @(Get-WmiObject Win32_BaseBoard)) { $sum += 'Board        : {0} {1}' -f $b.Manufacturer, $b.Product }
foreach ($b in @(Get-WmiObject Win32_BIOS)) { $sum += 'BIOS         : {0} {1}' -f $b.SMBIOSBIOSVersion, $b.ReleaseDate }
foreach ($c in @(Get-WmiObject Win32_Processor)) { $sum += 'CPU          : {0}' -f $c.Name.Trim() }
$sum += 'RAM          : {0:N1} GB' -f ($cs.TotalPhysicalMemory / 1GB)
foreach ($d in @(Get-WmiObject Win32_DiskDrive)) { $sum += 'Disk         : {0}, {1:N0} GB, {2}' -f $d.Model, ($d.Size / 1GB), $d.InterfaceType }
$diskPath = Join-Path $root 'info\disks.txt'
$volumes = @()
if (Test-Path -LiteralPath $diskPath) {
    $volumes = @(Get-Content -LiteralPath $diskPath -Encoding UTF8 | Where-Object { $_ -like 'Volume       : *' })
}
if ($volumes.Count) { $sum += $volumes }
elseif ($sysFree -ne $null) { $sum += 'Volume       : {0} {1:N1} GB free (at start; disk snapshot incomplete)' -f $sysDrive.TrimEnd('\'), ($sysFree / 1GB) }
$sum += 'PowerShell   : {0}' -f $PSVersionTable.PSVersion
$sum += ''
$sum += 'Event logs (records  channel):'
$sum += $evtStat
$sum += ''
$sum += 'Dump mode    : {0}' -f $dumpMode   # the configured mode, not a count of dumps found
$sum += 'WER          : {0}' -f $werState
$sum += ''
$sum += 'Dumps:'
$sum += $dumpChecked
if ($dumpList.Count) { $sum += $dumpList } else { $sum += '  none found' }
$sum += ''
$sum += 'Report.wer taken: {0}' -f $wer.Count
$sum += ''
$sum += 'Failed steps: {0}' -f $fails.Count
$sum += $fails
$sum | Out-File (Join-Path $root '00-summary.txt') -Encoding UTF8

# Manifest for checking the copy later: sha256sum -c 00-manifest.sha256 (paths with /, LF, no BOM)
Say 'Hashing'
$sha = [Security.Cryptography.SHA256]::Create()
function Hash-Lines($files) {
    foreach ($f in $files) {
        $fs = [IO.File]::OpenRead($f.FullName)
        try { $h = ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '' } finally { $fs.Close() }
        '{0}  {1}' -f $h, ($f.FullName.Substring($root.Length + 1) -replace '\\', '/')
    }
}
$manifest = Join-Path $root '00-manifest.sha256'
$inputs = @(Get-ChildItem $root -Recurse | Where-Object {
    -not $_.PSIsContainer -and (('00-journal.txt', '00-manifest.sha256') -notcontains $_.Name)
})
$lines = @(Hash-Lines $inputs)
[IO.File]::WriteAllText($manifest, (($lines -join "`n") + "`n"))

# Generate the report from the verified capture before packing it. Stage the output outside the
# capture, then put the HTML in the capture root so it is easy to find after extraction.
$pythonVersion = if ([version]$os.Version -lt [version]'6.3') { '3.8' } else { '3.13' }
Say ('Offline analysis (Python {0})' -f $pythonVersion)
$python = Join-Path $toolsDir ('python\{0}\python.exe' -f $pythonVersion)
$analyzer = Join-Path $scriptDir 'health.py'
if ((Test-Path -LiteralPath $python -PathType Leaf) -and (Test-Path -LiteralPath $analyzer -PathType Leaf)) {
    $scratch = Join-Path $tmpDir ('anamnez-report-' + [guid]::NewGuid())
    $reports = 'health.txt', 'health.json', 'health.html'
    $published = @()
    try {
        Run-Exe $python ('-B -X utf8 "{0}" "{1}" -o "{2}"' -f $analyzer, $root, $scratch) 'analyzer.txt' 600
        if ($script:exeExit -ne 0) { throw ('Analyzer exit {0}. See info\analyzer.txt and any .err file.' -f $script:exeExit) }
        foreach ($leaf in $reports) {
            $staged = Join-Path $scratch $leaf
            $target = Join-Path $root $leaf
            [IO.File]::Copy($staged, $target, $false)
            $published += $target
        }
        Say '   Open health.html in the result.'
    } catch {
        foreach ($target in $published) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
        Fail ('Offline analysis: {0}' -f $_)
    } finally {
        if (Test-Path -LiteralPath $scratch) {
            Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $extraFiles = @()
    foreach ($relative in ($reports + @('info\analyzer.txt', 'info\analyzer.txt.err'))) {
        $path = Join-Path $root $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) { $extraFiles += Get-Item -LiteralPath $path }
    }
    if ($extraFiles.Count) {
        $extraLines = @(Hash-Lines $extraFiles)
        [IO.File]::AppendAllText($manifest, (($extraLines -join "`n") + "`n"))
    }
} else {
    Fail 'Offline analysis: portable Python or analyzer missing. Use the complete Anamnez package.'
}
$sha.Clear()

# ---------- 6. Pack and deliver ----------
Say '6/6 Pack and deliver'
$total = 0; foreach ($f in @(Get-ChildItem $root -Recurse | Where-Object { -not $_.PSIsContainer })) { $total += $f.Length }
Say ('   collected {0:N1} MB' -f ($total / 1MB))

# One archive reduces the size of the capture and lets 7-Zip check its integrity.
# Prefer the standalone 7zr.exe. The full 7z.exe requires its DLL.
$arc = $null
$sevenZip = Find-Tool '7zr.exe', '7za.exe', '7z.exe'
if ($sevenZip) {
    $a = $root + '.7z'
    if (Test-Path -LiteralPath $a) { Remove-Item -LiteralPath $a -Force }
    Run-Exe $sevenZip ('a -t7z -mx=5 -bd -y "{0}" "{1}"' -f $a, $root) '' 900   # folder itself: unpacks into <name>\
    if ($script:exeExit -eq 0) {
        Run-Exe $sevenZip ('t -bd "{0}"' -f $a) '' 300
        if ($script:exeExit -eq 0) { $arc = $a; Say ('   packed {0:N1} MB' -f ((Get-Item -LiteralPath $a).Length / 1MB)) }
        else { Fail ('7-Zip test: exit {0}, result stays an unpacked folder' -f $script:exeExit) }
    } else { Fail ('7-Zip pack: exit {0}, result stays an unpacked folder' -f $script:exeExit) }
} else { Say '   7-Zip not found under tools\ - result stays an unpacked folder' 'DarkGray' }

# Use the launch drive when it has at least 1 GB free and enough space for the result.
# Keep the working copy until the delivered copy passes verification.
if ($arc) { $need = (Get-Item -LiteralPath $arc).Length } else { $need = $total }
$onStick = $false
if (-not $workOnStick -and $stick -ne ($env:SystemDrive + '\')) {
    $free = Free-Bytes $stick
    if ($free -eq $null -or ($free -ge 1GB -and $free -ge $need * 1.05)) { $onStick = $true }
    else { Say ('   stick {0}: {1:N0} MB free (< 1 GB) - result stays on C:' -f $stick, ($free / 1MB)) 'Yellow' }
}

$result = $null
if ($workOnStick) {
    # Already on the stick in <stick>:\evt\ - the archive (tested above) or the folder is the result
    if ($arc) { $result = $arc } else { $result = $root }
} elseif (-not $onStick) {
    if ($arc) { $result = $arc } else { $result = $root }
} else {
    $destDir = Join-Path $stick 'evt'
    $copied = $false
    try {
        New-Item -ItemType Directory -Force -Path $destDir -ErrorAction Stop | Out-Null
        if ($arc) { Copy-Item -LiteralPath $arc $destDir -Force -ErrorAction Stop }
        else { Copy-Item $root $destDir -Recurse -Force -ErrorAction Stop }
        $copied = $true
    } catch { Fail ('copy to stick: {0}' -f $_) }
    if ($copied -and $arc) {
        # Verify the delivered archive by both file size and CRC.
        $dest = Join-Path $destDir ($name + '.7z')
        $ok = (Test-Path -LiteralPath $dest) -and (Get-Item -LiteralPath $dest).Length -eq (Get-Item -LiteralPath $arc).Length
        if ($ok) { Run-Exe $sevenZip ('t -bd "{0}"' -f $dest) '' 300; $ok = $script:exeExit -eq 0 }
        if ($ok) { $result = $dest } else { Fail ('archive on stick is broken: {0}' -f $dest) }
    } elseif ($copied) {
        $dest = Join-Path $destDir $name
        # Verify file sizes and check signatures when the format is known.
        $bad = 0
        foreach ($f in @(Get-ChildItem $root -Recurse | Where-Object { -not $_.PSIsContainer -and $_.Name -ne '00-journal.txt' })) {
            $t = Join-Path $dest $f.FullName.Substring($root.Length + 1)
            if (-not (Test-Path -LiteralPath $t) -or (Get-Item -LiteralPath $t).Length -ne $f.Length) { $bad++; Fail ('size mismatch: {0}' -f $t); continue }
            $sig = $null
            if ($f.Extension -eq '.evtx') { $sig = 'ElfFile' } elseif ($f.Extension -eq '.dmp') { $sig = 'PAGE' }
            if ($sig -and $f.Length -ge 8) {
                $fs = [IO.File]::OpenRead($t); $buf = New-Object byte[] 8; [void]$fs.Read($buf, 0, 8); $fs.Close()
                if (-not ([Text.Encoding]::ASCII.GetString($buf)).StartsWith($sig)) { $bad++; Fail ('bad signature: {0}' -f $t) }
            }
        }
        if ($bad -eq 0) { $result = $dest }
    }
}

Say ('Done. Failed steps: {0} (see 00-summary.txt)' -f $fails.Count) 'Cyan'
if ($result -and $result -ne $root -and (Test-Path -LiteralPath $result -PathType Container)) {
    Copy-Item $journal $result -Force   # unpacked folder on the stick: journal with the final lines
}
# Remove the working copies; from here on the journal folder may be gone, so plain Write-Host
if ($result) {
    if ($result -ne $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    if ($arc -and $result -ne $arc) { Remove-Item -LiteralPath $arc -Force -ErrorAction SilentlyContinue }
    Write-Host ('RESULT: {0}' -f $result) -ForegroundColor Green
} else {
    Write-Host ('Delivery failed - everything is left in {0}' -f (Split-Path $root)) -ForegroundColor Red
}
[void](Read-Host 'Press Enter to close')
