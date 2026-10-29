#Requires -Version 5.1
<#
.SYNOPSIS
    Mount Windows installation media read-only and build a verified PE corpus from it.

.DESCRIPTION
    Hashes the source, mounts it read-only (ISO, WIM, ESD, VHD) or takes a directory as it is,
    runs collect_pes.py against the mount, records the media in source.json, then runs
    verify_corpus.py. Every mount, and the temporary WIM of an ESD, is removed in a finally
    block, also after an error or Ctrl+C.

    Nothing is written inside the source. Nothing is deleted unless -DeleteSource is passed and
    verification passed.

    Log lines follow the os-corpus conventions (USAGE.md): [i] information, [>] a step being
    run, [+] done, [~] skipped or a warning, [!] an error (stderr).

    Exit codes: 0 success, 1 error, 2 bad usage or an edition listing, 3 collisions, 4 or 5
    verification failed (see verify_corpus.py), 130 collection interrupted.

.PARAMETER Iso
    An ISO. Mounted read-only; install.wim or install.esd is taken from \sources.

.PARAMETER Wim
    An install.wim, or an install.esd together with -ConvertEsd.

.PARAMETER Vhd
    A VHD/VHDX. The Windows volume inside is scanned, or its \sources\install.wim. Needs the
    Hyper-V PowerShell module.

.PARAMETER Directory
    An already-mounted or extracted tree. Needs no elevation.

.PARAMETER Out
    Corpus directory. Stored files keep their image path inside it.

.PARAMETER Report
    Report directory. Default: <Out>\..\manifests\<Label>.

.PARAMETER Index
    WIM/ESD image index. 0 (the default) lists the editions and exits with code 2.

.PARAMETER Label
    Name of the build, used for the report directory and summary.json. Default: the name of
    Out. Characters other than letters, digits, '.', '_' and '-' become '_'.

.PARAMETER Arch
    Architecture filter passed to collect_pes.py, e.g. "x64,x86".

.PARAMETER Python
    Python interpreter to run the tools with. Default: python.

.PARAMETER Resume
    Continue an interrupted run into the same Out (collect_pes.py --resume).

.PARAMETER Force
    Allow a non-empty Out (collect_pes.py --force).

.PARAMETER NoVerify
    Skip the verification pass. Cannot be combined with -DeleteSource.

.PARAMETER ConvertEsd
    Export the chosen image of an install.esd to a temporary WIM (<Out>\..\.tmp) before
    mounting. Needs room for the image; the temporary WIM is deleted afterwards.

.PARAMETER DeleteSource
    Delete the ISO after verification passed. Only valid with -Iso, never with -NoVerify.

.EXAMPLE
    .\extract-image.ps1 -Iso D:\media\Win10_22H2.iso -Out D:\corpus\10.0.19045
    Lists the editions on the media and exits with code 2.

.EXAMPLE
    .\extract-image.ps1 -Iso D:\media\Win10_22H2.iso -Out D:\corpus\10.0.19045 -Index 6 -Label 10.0.19045
    Collects edition 6 and verifies it.

.EXAMPLE
    .\extract-image.ps1 -Wim D:\media\install.esd -ConvertEsd -Index 4 -Out D:\corpus\26200

.EXAMPLE
    .\extract-image.ps1 -Directory C:\mnt\windows -Out D:\corpus\sample -Label sample
#>
[CmdletBinding(DefaultParameterSetName = 'Iso')]
param(
    [Parameter(ParameterSetName = 'Iso', Mandatory = $true, Position = 0)]
    [string] $Iso,

    [Parameter(ParameterSetName = 'Wim', Mandatory = $true, Position = 0)]
    [string] $Wim,

    [Parameter(ParameterSetName = 'Vhd', Mandatory = $true, Position = 0)]
    [string] $Vhd,

    [Parameter(ParameterSetName = 'Directory', Mandatory = $true, Position = 0)]
    [string] $Directory,

    [Parameter(Mandatory = $true, Position = 1)]
    [string] $Out,

    [string] $Report,
    [int] $Index = 0,
    [string] $Label,
    [string] $Arch,
    [string] $Python = 'python',
    [switch] $Resume,
    [switch] $Force,
    [switch] $NoVerify,
    [switch] $ConvertEsd,
    [switch] $DeleteSource
)

$ErrorActionPreference = 'Stop'

# ---- CONFIG ----

$ExitOk = 0
$ExitError = 1
$ExitUsage = 2
$ExitCollisions = 3
$ExitInterrupted = 130

$SourceSchema = 'os-corpus/source/1'

# Get-WindowsImage Architecture values.
$ImageArch = @{ 0 = 'x86'; 5 = 'arm'; 6 = 'ia64'; 9 = 'x64'; 12 = 'arm64' }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Collect = Join-Path $ScriptDir 'collect_pes.py'
$Verify = Join-Path $ScriptDir 'verify_corpus.py'
$Pelib = Join-Path $ScriptDir 'pelib.py'

# ---- OUTPUT ----

function Write-Info([string] $Text) { Write-Host "[i] $Text" }
function Write-Run([string] $Text) { Write-Host "[>] $Text" }
function Write-Done([string] $Text) { Write-Host "[+] $Text" }
function Write-Skip([string] $Text) { Write-Host "[~] $Text" }
function Write-Fail([string] $Text) {
    [Console]::Out.Flush()
    [Console]::Error.WriteLine("[!] extract-image: $Text")
}

# ---- HELPERS ----

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Images([string] $Path) {
    Get-WindowsImage -ImagePath $Path |
        Select-Object ImageIndex, ImageName, ImageDescription |
        Format-Table -AutoSize |
        Out-String -Width 220 |
        Write-Host
}

function Get-ToolVersion {
    $value = & $Python $Pelib version 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $value) { return '0.0.0' }
    return ([string] $value).Trim()
}

function Get-PeRevision([string] $DllPath) {
    if (-not (Test-Path -LiteralPath $DllPath)) { return '' }
    $raw = & $Python $Pelib info $DllPath 2>$null
    if ($LASTEXITCODE -eq 0 -and $raw) {
        try {
            $parsed = ($raw -join "`n") | ConvertFrom-Json
            if ($parsed.file_version) { return [string] $parsed.file_version }
        } catch { }
    }
    return [string] (Get-Item -LiteralPath $DllPath).VersionInfo.FileVersion
}

function Get-FileSha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# The DISM description of one image, as recorded in source.json.
function Get-ContainerRecord($Info, [string] $Name, [int] $ImageIndex) {
    $build = ''
    if ($null -ne $Info.MajorVersion -and $null -ne $Info.Build) {
        $build = '{0}.{1}.{2}.{3}' -f $Info.MajorVersion, $Info.MinorVersion, $Info.Build, $Info.SPBuild
    }
    $arch = ''
    if ($null -ne $Info.Architecture) {
        $arch = $ImageArch[[int] $Info.Architecture]
        if (-not $arch) { $arch = [string] $Info.Architecture }
    }
    return [ordered]@{
        name             = $Name
        imageIndex       = $ImageIndex
        imageName        = [string] $Info.ImageName
        edition          = [string] $Info.EditionId
        installationType = [string] $Info.InstallationType
        architecture     = $arch
        build            = $build
        languages        = @($Info.Languages | ForEach-Object { [string] $_ })
    }
}

# UTF-8 without a BOM and LF line ends, like every other report.
function Write-TextFile([string] $Path, [string] $Text) {
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, (($Text -replace "`r`n", "`n").TrimEnd("`n") + "`n"), $encoding)
}

# ---- VALIDATION ----

if ($DeleteSource -and $NoVerify) {
    Write-Fail '-DeleteSource needs verification; it cannot be combined with -NoVerify'
    exit $ExitUsage
}
if ($DeleteSource -and $PSCmdlet.ParameterSetName -ne 'Iso') {
    Write-Fail '-DeleteSource only applies to -Iso'
    exit $ExitUsage
}
if ($Index -lt 0) {
    Write-Fail '-Index must be 0 (list the editions) or an image index'
    exit $ExitUsage
}
foreach ($file in @($Collect, $Verify, $Pelib)) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Fail "missing companion script: $file"
        exit $ExitError
    }
}
try {
    $null = & $Python --version 2>&1
} catch {
    Write-Fail "cannot run Python ('$Python'): $($_.Exception.Message)"
    exit $ExitError
}
if ($PSCmdlet.ParameterSetName -ne 'Directory' -and -not (Test-IsAdmin)) {
    Write-Fail 'mounting media needs an elevated PowerShell session'
    exit $ExitError
}

$fsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
$longPaths = (Get-ItemProperty -LiteralPath $fsKey -Name LongPathsEnabled -ErrorAction SilentlyContinue).LongPathsEnabled
if ($longPaths -ne 1) {
    Write-Skip 'LongPathsEnabled is not set; the tools use \\?\ paths, other programs may not'
}

$Out = [IO.Path]::GetFullPath($Out)
$Parent = Split-Path -Parent $Out
if (-not $Label) { $Label = Split-Path -Leaf $Out }
$Label = $Label -replace '[^A-Za-z0-9._-]', '_'
if (-not $Report) {
    $Report = Join-Path (Join-Path $Parent 'manifests') $Label
}
$Report = [IO.Path]::GetFullPath($Report)
if ($Report.StartsWith($Out + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Fail "report directory must be outside the corpus: $Report"
    exit $ExitUsage
}

# ---- STATE ----
# Everything the finally block may have to undo.

$Kind = ''
$ImageName = ''
$ImageBytes = 0
$ImageSha = ''
$Container = $null
$ImagePath = ''
$IsoPath = ''
$ScanRoot = ''
$MountDir = ''
$MountIndex = 0
$WimMounted = $false
$DiskPath = ''
$VhdPath = ''
$VhdMounted = $false
$ConvertedWim = ''
$Listed = $false
$CollectCode = 0
$VerifyCode = 0
$script:FinalCode = $ExitOk

try {
    $ToolVersion = Get-ToolVersion
    Write-Info "os-corpus $ToolVersion, build $Label"

    switch ($PSCmdlet.ParameterSetName) {
        'Directory' {
            $Kind = 'directory'
            $ScanRoot = [IO.Path]::GetFullPath($Directory)
            if (-not (Test-Path -LiteralPath $ScanRoot -PathType Container)) {
                throw "not a directory: $ScanRoot"
            }
            $ImageName = Split-Path -Leaf $ScanRoot
        }

        'Iso' {
            $Kind = 'iso'
            $IsoPath = [IO.Path]::GetFullPath($Iso)
            if (-not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
                throw "no such ISO: $IsoPath"
            }
            $ImageName = Split-Path -Leaf $IsoPath
            $ImageBytes = (Get-Item -LiteralPath $IsoPath).Length
            Write-Run "hashing $ImageName"
            $ImageSha = Get-FileSha256 $IsoPath

            $disk = Get-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue
            if ($disk -and $disk.Attached) {
                Write-Info 'ISO is already mounted; it is left mounted afterwards'
            } else {
                Write-Run 'mounting ISO read-only'
                $disk = Mount-DiskImage -ImagePath $IsoPath -Access ReadOnly -PassThru
                $DiskPath = $IsoPath
            }
            $volume = $disk | Get-Volume | Select-Object -First 1
            if (-not $volume -or -not $volume.DriveLetter) {
                throw 'mounted ISO has no drive letter'
            }
            $sources = "$($volume.DriveLetter):\sources"
            if (-not (Test-Path -LiteralPath $sources)) {
                throw 'no \sources directory on the media; is this a Windows ISO?'
            }
            foreach ($candidate in @('install.wim', 'install.esd')) {
                $path = Join-Path $sources $candidate
                if (Test-Path -LiteralPath $path) { $ImagePath = $path; break }
            }
            if (-not $ImagePath) {
                throw "no install.wim or install.esd in $sources"
            }
        }

        'Wim' {
            $Kind = 'wim'
            $ImagePath = [IO.Path]::GetFullPath($Wim)
            if (-not (Test-Path -LiteralPath $ImagePath -PathType Leaf)) {
                throw "no such image: $ImagePath"
            }
            $ImageName = Split-Path -Leaf $ImagePath
            $ImageBytes = (Get-Item -LiteralPath $ImagePath).Length
            Write-Run "hashing $ImageName"
            $ImageSha = Get-FileSha256 $ImagePath
        }

        'Vhd' {
            $Kind = 'vhd'
            $VhdPath = [IO.Path]::GetFullPath($Vhd)
            if (-not (Test-Path -LiteralPath $VhdPath -PathType Leaf)) {
                throw "no such VHD: $VhdPath"
            }
            if (-not (Get-Command Mount-VHD -ErrorAction SilentlyContinue)) {
                throw 'Mount-VHD is not available on this host (Hyper-V PowerShell module missing)'
            }
            $ImageName = Split-Path -Leaf $VhdPath
            $ImageBytes = (Get-Item -LiteralPath $VhdPath).Length
            Write-Run "hashing $ImageName"
            $ImageSha = Get-FileSha256 $VhdPath

            Write-Run 'mounting VHD read-only'
            $disk = Mount-VHD -Path $VhdPath -ReadOnly -PassThru
            $VhdMounted = $true
            $volumes = Get-Disk -Number $disk.Number | Get-Partition | Get-Volume |
                Where-Object { $_.DriveLetter }
            foreach ($candidate in $volumes) {
                $root = "$($candidate.DriveLetter):\"
                if (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\ntdll.dll')) {
                    $ScanRoot = $root
                    break
                }
                if (Test-Path -LiteralPath (Join-Path $root 'sources\install.wim')) {
                    $ImagePath = Join-Path $root 'sources\install.wim'
                    break
                }
            }
            if (-not $ScanRoot -and -not $ImagePath) {
                throw 'no Windows volume and no install.wim inside the VHD'
            }
        }
    }

    if ($ImagePath) {
        $containerName = Split-Path -Leaf $ImagePath
        $isEsd = [IO.Path]::GetExtension($ImagePath) -ieq '.esd'
        if ($isEsd -and -not $ConvertEsd) {
            throw 'ESD images cannot be mounted; pass -ConvertEsd to export the image to a temporary WIM first'
        }

        if ($Index -eq 0) {
            Write-Info "editions in $containerName"
            Show-Images $ImagePath
            Write-Info 'nothing collected; re-run with -Index <n> (on server media, the Desktop Experience edition)'
            $Listed = $true
            $script:FinalCode = $ExitUsage
        } else {
            $selected = Get-WindowsImage -ImagePath $ImagePath -Index $Index -ErrorAction SilentlyContinue
            if (-not $selected) {
                Show-Images $ImagePath
                throw "image index $Index does not exist in $ImagePath"
            }
            $Container = Get-ContainerRecord $selected $containerName $Index
            Write-Info ("image {0}: {1}, {2}, {3}" -f $Index, $Container.imageName, $Container.architecture, $Container.build)

            $MountIndex = $Index
            if ($isEsd) {
                $tmpDir = Join-Path $Parent '.tmp'
                New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
                $ConvertedWim = Join-Path $tmpDir ($Label + '.wim')
                if (Test-Path -LiteralPath $ConvertedWim) {
                    throw "temporary WIM already exists: $ConvertedWim (left by an earlier run; remove it)"
                }
                Write-Run "exporting image $Index to $ConvertedWim (slow)"
                $sourceArg = '/SourceImageFile:{0}' -f $ImagePath
                $destArg = '/DestinationImageFile:{0}' -f $ConvertedWim
                & dism.exe /English /Export-Image $sourceArg "/SourceIndex:$Index" $destArg /Compress:max | Out-Host
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ConvertedWim)) {
                    throw "dism export failed with exit code $LASTEXITCODE"
                }
                # The exported WIM holds this one image, at index 1.
                $ImagePath = $ConvertedWim
                $MountIndex = 1
            }

            $MountDir = Join-Path (Join-Path $Parent '.mnt') $Label
            if (Test-Path -LiteralPath $MountDir) {
                if (Get-ChildItem -LiteralPath $MountDir -Force | Select-Object -First 1) {
                    throw "mount directory is not empty: $MountDir (dismount it or remove it)"
                }
            } else {
                New-Item -ItemType Directory -Force -Path $MountDir | Out-Null
            }
            Write-Run "mounting image $Index read-only"
            Mount-WindowsImage -ImagePath $ImagePath -Index $MountIndex -Path $MountDir -ReadOnly | Out-Null
            $WimMounted = $true
            $ScanRoot = $MountDir
        }
    }

    if (-not $Listed) {
        if (-not $ScanRoot) {
            throw 'could not resolve a directory to scan'
        }

        $collectArgs = @($Collect, $ScanRoot, $Out, '--report', $Report, '--label', $Label)
        if ($Arch) { $collectArgs += @('--arch', $Arch) }
        if ($Resume) { $collectArgs += '--resume' }
        if ($Force) { $collectArgs += '--force' }

        Write-Run "collecting from $ScanRoot"
        & $Python @collectArgs | Out-Host
        $CollectCode = $LASTEXITCODE
        if ($CollectCode -eq $ExitInterrupted) {
            $script:FinalCode = $ExitInterrupted
            throw 'collection was interrupted; re-run with -Resume'
        }
        if ($CollectCode -ne $ExitOk -and $CollectCode -ne $ExitCollisions) {
            throw "collection failed with exit code $CollectCode"
        }

        $manifestPath = Join-Path $Report 'manifest.sha256'
        if (-not (Test-Path -LiteralPath $manifestPath)) {
            throw "collection wrote no manifest: $manifestPath"
        }
        $manifestLines = @(Get-Content -LiteralPath $manifestPath).Count

        $source = [ordered]@{
            schema         = $SourceSchema
            tool           = [ordered]@{ name = 'os-corpus'; version = $ToolVersion }
            kind           = $Kind
            image          = [ordered]@{ name = $ImageName; bytes = $ImageBytes; sha256 = $ImageSha }
            container      = $Container
            revision       = Get-PeRevision (Join-Path $Out 'Windows\System32\ntdll.dll')
            manifestSha256 = Get-FileSha256 $manifestPath
            collectedFiles = $manifestLines
            acquired       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        Write-TextFile (Join-Path $Report 'source.json') ($source | ConvertTo-Json -Depth 6)
        Write-Done 'source.json'

        if ($NoVerify) {
            Write-Skip 'verification skipped (-NoVerify); the corpus is not verified'
        } else {
            Write-Run 'verifying'
            $verifyArgs = @($Verify, $Out, '--report', $Report)
            if ($CollectCode -eq $ExitCollisions) { $verifyArgs += '--allow-collisions' }
            & $Python @verifyArgs | Out-Host
            $VerifyCode = $LASTEXITCODE
        }

        Write-Info "build       $Label"
        Write-Info "revision    $($source.revision)"
        Write-Info "files       $manifestLines"
        Write-Info "corpus      $Out"
        Write-Info "report      $Report"

        if ($VerifyCode -ne $ExitOk) {
            $script:FinalCode = $VerifyCode
            Write-Fail "verification failed with exit code $VerifyCode; the corpus is not trustworthy yet"
        } else {
            $script:FinalCode = $CollectCode
            if ($CollectCode -eq $ExitCollisions) {
                Write-Fail 'collisions: a path was found twice; see collisions.tsv'
            }
        }

        if ($DeleteSource) {
            if ($script:FinalCode -eq $ExitOk) {
                if ($DiskPath) {
                    Dismount-DiskImage -ImagePath $DiskPath -ErrorAction Stop | Out-Null
                    $DiskPath = ''
                }
                Write-Run "deleting $IsoPath"
                Remove-Item -LiteralPath $IsoPath -Force
                Write-Done "deleted $IsoPath"
            } else {
                Write-Skip 'source kept because the run did not pass'
            }
        }

        if ($script:FinalCode -eq $ExitOk) {
            Write-Done "extract-image: $Label, $manifestLines files, verified"
        }
    }
}
catch {
    Write-Fail $_.Exception.Message
    if ($script:FinalCode -eq $ExitOk -or $script:FinalCode -eq $ExitUsage) {
        $script:FinalCode = $ExitError
    }
}
finally {
    if ($WimMounted -and $MountDir) {
        Write-Run 'dismounting image'
        try {
            Dismount-WindowsImage -Path $MountDir -Discard -ErrorAction Stop | Out-Null
        } catch {
            Write-Skip "image dismount failed: $($_.Exception.Message)"
        }
    }
    if ($DiskPath) {
        try {
            Dismount-DiskImage -ImagePath $DiskPath -ErrorAction Stop | Out-Null
        } catch {
            Write-Skip "ISO dismount failed: $($_.Exception.Message)"
        }
    }
    if ($VhdMounted -and $VhdPath) {
        try {
            Dismount-VHD -Path $VhdPath -ErrorAction Stop
        } catch {
            Write-Skip "VHD dismount failed: $($_.Exception.Message)"
        }
    }
    if ($MountDir -and (Test-Path -LiteralPath $MountDir)) {
        if (Get-ChildItem -LiteralPath $MountDir -Force | Select-Object -First 1) {
            Write-Skip "mount directory still has content: $MountDir"
        } else {
            Remove-Item -LiteralPath $MountDir -Force -ErrorAction SilentlyContinue
        }
    }
    if ($ConvertedWim -and (Test-Path -LiteralPath $ConvertedWim)) {
        try {
            Remove-Item -LiteralPath $ConvertedWim -Force -ErrorAction Stop
            $tmpDir = Split-Path -Parent $ConvertedWim
            if (-not (Get-ChildItem -LiteralPath $tmpDir -Force | Select-Object -First 1)) {
                Remove-Item -LiteralPath $tmpDir -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Skip "temporary WIM not removed: $ConvertedWim"
        }
    }
}

exit $script:FinalCode
