<#
.SYNOPSIS
    Offline, zero-dependency CLI wrapper for Invoke-AuditRunner.ps1 (Windows-first).

.DESCRIPTION
    Thin picker + progress + summary layer over Invoke-AuditRunner.ps1.
    Works out-of-box after `git clone` in an OFFLINE environment: no modules,
    no downloads, no Python/Textual. Compatible with Windows PowerShell 5.1
    and PowerShell 7 (pwsh).

    OFFLINE NOTE: this wrapper and the bundled runners work fully offline.
    They only read the local .audit file and query local host policy
    (secedit.exe / auditpol.exe / registry / CIM). Nothing is downloaded,
    uploaded, or resolved over the network.

    Exit codes: 0 on success (even when rows are Fail/Manual — writing the
    CSV is success). Non-zero only on usage errors or missing input files.

.EXAMPLE
    .\Invoke-AuditRunnerCli.ps1 -AuditPath C:\Audits\benchmark.audit
    Runs an audit; the runner writes <input>_results_<timestamp>.csv beside
    the script, then this CLI prints a colored summary.

.EXAMPLE
    .\Invoke-AuditRunnerCli.ps1 -AuditPath C:\Audits\benchmark.audit -ExportChecksPath .\benchmark_checks.csv -OutputPath .\results.csv
    .\Invoke-AuditRunnerCli.ps1 -ChecksPath .\benchmark_checks.csv -OutputPath .\results2.csv
    Reusable catalog: export once (export still runs the checks), then re-run
    later without the .audit file.

.EXAMPLE
    .\Invoke-AuditRunnerCli.ps1 -ShowMatrix
    Prints the supported check-type matrix (parity for `audit matrix`).
#>
[CmdletBinding()]
param(
    [string]$AuditPath = '',
    [string]$ChecksPath = '',
    [string]$OutputPath = '',
    [string]$ExportChecksPath = '',
    [switch]$AllowEmbeddedScripts,
    [string]$HtmlPath = '',
    [string]$CompanyName = '',
    [string]$ClientName = '',
    [string]$AssessorName = '',
    [string]$ReportTitle = '',
    [string]$LogoPath = '',
    [switch]$Quiet,
    [switch]$ShowMatrix,
    [Alias('?')][switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AuditCliScriptDirectory {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    return (Get-Location).Path
}

function Show-AuditCliHelp {
    @'
Invoke-AuditRunnerCli.ps1 — offline CLI wrapper for AuditRunner (Windows-first).

USAGE:
    .\Invoke-AuditRunnerCli.ps1 [-AuditPath <file.audit>] [-ChecksPath <checks.csv>]
        [-OutputPath <results.csv>] [-ExportChecksPath <checks.csv>]
        [-AllowEmbeddedScripts] [-HtmlPath <report.html>]
        [-CompanyName <n>] [-ClientName <n>] [-AssessorName <n>]
        [-ReportTitle <t>] [-LogoPath <logo.png>]
        [-Quiet] [-ShowMatrix] [-Help]

OPTIONS:
    -AuditPath <path>       Nessus .audit file to evaluate. Wins if both
                            -AuditPath and -ChecksPath are given.
    -ChecksPath <path>      Reusable checks catalog CSV (exported earlier).
    -OutputPath <path>      Results CSV path. Default:
                            <input>_results_<timestamp>.csv beside the script.
                            Missing parent folders are created.
    -ExportChecksPath <path> Export the parsed checks catalog AND still run
                            the checks (not parse-only).
    -AllowEmbeddedScripts   Opt-in: allow embedded-script checks. Off by
                            default; without it such checks report Manual.
                            Only use with reviewed, trusted audit files.
    -HtmlPath <path>        Also write a self-contained offline HTML report
                            (white-label: -CompanyName, -ClientName,
                            -AssessorName, -ReportTitle, -LogoPath for a
                            local image file embedded as data URI).
    -CompanyName <text>     Branding for the HTML report header.
    -ClientName <text>      Client name shown in the HTML report header.
    -AssessorName <text>    Assessor name shown in the HTML report header.
    -ReportTitle <text>     Title for the HTML report.
    -LogoPath <path>        Local logo file (png/jpg/gif/svg) embedded in
                            the HTML report; ignored if missing.
    -Quiet                  Summary only: suppress per-check result lines.
    -ShowMatrix             Print the supported type matrix
                             (tools/Get-AuditRunnerMatrix.ps1) and exit.
    -Help, -?               Show this help and exit.

OFFLINE NOTE: fully offline after `git clone`. Zero dependencies — Windows
PowerShell 5.1 and pwsh compatible, no modules, no downloads. Only the local
.audit file and local host policy are read; nothing leaves the machine.

EXAMPLES:
    # 1. Run an audit (prompts with a numbered picker if no file is given)
    .\Invoke-AuditRunnerCli.ps1 -AuditPath C:\Audits\benchmark.audit

    # 2. Catalog export, then re-run later without the .audit file
    .\Invoke-AuditRunnerCli.ps1 -AuditPath C:\Audits\benchmark.audit -ExportChecksPath .\benchmark_checks.csv -OutputPath .\results.csv
    .\Invoke-AuditRunnerCli.ps1 -ChecksPath .\benchmark_checks.csv -OutputPath .\results2.csv

    # 3. Show the supported check-type matrix (parity for `audit matrix`)
    .\Invoke-AuditRunnerCli.ps1 -ShowMatrix

EXIT CODES: 0 on success (even with Fail/Manual rows — writing the CSV is
success). Non-zero only on usage errors or missing input files.
'@
}

function Show-AuditCliBanner {
    Write-Host ''
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host '   AuditRunner  //  offline audit CLI' -ForegroundColor Cyan
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host ''
}

function Test-AuditCliElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $null
    }
}

function Ensure-DirectoryExists {
    param([string]$DirectoryPath)
    if ([string]::IsNullOrWhiteSpace($DirectoryPath)) { return }
    if (-not (Test-Path -LiteralPath $DirectoryPath)) {
        [void](New-Item -ItemType Directory -Force -Path $DirectoryPath)
    }
}

function Get-FullCliPath {
    param([string]$Path)
    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    } catch {
        if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
        return (Join-Path (Get-Location).Path $Path)
    }
}

$scriptDir = Get-AuditCliScriptDirectory

if ($Help) {
    Show-AuditCliHelp
    exit 0
}

if ($ShowMatrix) {
    $matrixScript = Join-Path $scriptDir 'tools/Get-AuditRunnerMatrix.ps1'
    if (-not (Test-Path -LiteralPath $matrixScript)) {
        Write-Error "Support-matrix script not found: $matrixScript"
        exit 1
    }
    & $matrixScript
    exit $LASTEXITCODE
}

if (-not [string]::IsNullOrWhiteSpace($AuditPath) -and -not [string]::IsNullOrWhiteSpace($ChecksPath)) {
    Write-Warning 'Both -AuditPath and -ChecksPath were given; -AuditPath wins.'
    $ChecksPath = ''
}

if ([string]::IsNullOrWhiteSpace($AuditPath) -and [string]::IsNullOrWhiteSpace($ChecksPath)) {
    $candidates = @()
    foreach ($searchDir in @((Get-Location).Path, $scriptDir)) {
        if ([string]::IsNullOrWhiteSpace($searchDir)) { continue }
        if (-not (Test-Path -LiteralPath $searchDir)) { continue }
        foreach ($found in (Get-ChildItem -LiteralPath $searchDir -Filter '*.audit' -File -ErrorAction SilentlyContinue)) {
            if ($candidates -notcontains $found.FullName) {
                $candidates += $found.FullName
            }
        }
    }
    if ($candidates.Count -eq 0) {
        Write-Error 'No input given and no *.audit files found in the current directory or script directory. Pass -AuditPath or -ChecksPath. (q to quit: just re-run and press Ctrl+C, or answer q below.)'
        exit 1
    }
    Write-Host 'Select an audit to run (q quits):' -ForegroundColor Cyan
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $candidates[$i])
    }
    Write-Host 'Hints: type a number, a file path, or q to quit.' -ForegroundColor DarkGray
    $choice = Read-Host 'Choice'
    if ($null -eq $choice -or $choice.Trim() -eq '' -or $choice.Trim().ToLowerInvariant() -eq 'q') {
        Write-Host 'Cancelled.'
        exit 0
    }
    $choice = $choice.Trim()
    $index = 0
    if ([int]::TryParse($choice, [ref]$index) -and $index -ge 1 -and $index -le $candidates.Count) {
        $AuditPath = $candidates[$index - 1]
    } else {
        $AuditPath = $choice
    }
}

$runnerPath = Join-Path $scriptDir 'Invoke-AuditRunner.ps1'
if (-not (Test-Path -LiteralPath $runnerPath)) {
    Write-Error "Runner not found: $runnerPath"
    exit 1
}

$effectiveInput = $AuditPath
$inputKind = 'audit'
if ([string]::IsNullOrWhiteSpace($effectiveInput)) {
    $effectiveInput = $ChecksPath
    $inputKind = 'checks catalog'
}
if (-not (Test-Path -LiteralPath $effectiveInput)) {
    Write-Error "$inputKind file not found: $effectiveInput"
    exit 1
}

$outputDir = $scriptDir
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $parent = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $outputDir = (Get-Location).Path
    } else {
        $outputDir = $parent
    }
}
Ensure-DirectoryExists -DirectoryPath $outputDir
if (-not [string]::IsNullOrWhiteSpace($ExportChecksPath)) {
    $exportParent = Split-Path -Parent $ExportChecksPath
    if (-not [string]::IsNullOrWhiteSpace($exportParent)) {
        Ensure-DirectoryExists -DirectoryPath $exportParent
    }
}
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $htmlParent = Split-Path -Parent $HtmlPath
    if (-not [string]::IsNullOrWhiteSpace($htmlParent)) {
        Ensure-DirectoryExists -DirectoryPath $htmlParent
    }
}

if (-not $Quiet) {
    Show-AuditCliBanner
}

Write-Host 'Preflight:' -ForegroundColor Cyan
$elevated = Test-AuditCliElevated
if ($null -eq $elevated) {
    Write-Host '  [?] elevated: n/a (non-Windows host)' -ForegroundColor Yellow
} elseif ($elevated) {
    Write-Host '  [ok] elevated session' -ForegroundColor Green
} else {
    Write-Host '  [--] not elevated (run as Administrator for full results)' -ForegroundColor Yellow
}
foreach ($toolName in @('secedit.exe', 'auditpol.exe')) {
    if (Get-Command $toolName -ErrorAction SilentlyContinue) {
        Write-Host ("  [ok] {0} present" -f $toolName) -ForegroundColor Green
    } else {
        Write-Host ("  [--] {0} missing (related checks report Manual)" -f $toolName) -ForegroundColor Yellow
    }
}
Write-Host ("  [ok] input ({0}): {1}" -f $inputKind, (Get-FullCliPath -Path $effectiveInput)) -ForegroundColor Green
Write-Host ("  [ok] output dir: {0}" -f (Get-FullCliPath -Path $outputDir)) -ForegroundColor Green

$runnerArgs = @{}
if (-not [string]::IsNullOrWhiteSpace($AuditPath)) { $runnerArgs['AuditPath'] = $AuditPath }
if (-not [string]::IsNullOrWhiteSpace($ChecksPath)) { $runnerArgs['ChecksPath'] = $ChecksPath }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $runnerArgs['OutputPath'] = $OutputPath }
if (-not [string]::IsNullOrWhiteSpace($ExportChecksPath)) { $runnerArgs['ExportChecksPath'] = $ExportChecksPath }
if ($AllowEmbeddedScripts) { $runnerArgs['AllowEmbeddedScripts'] = $true }
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) { $runnerArgs['HtmlPath'] = $HtmlPath }
if (-not [string]::IsNullOrWhiteSpace($CompanyName)) { $runnerArgs['CompanyName'] = $CompanyName }
if (-not [string]::IsNullOrWhiteSpace($ClientName)) { $runnerArgs['ClientName'] = $ClientName }
if (-not [string]::IsNullOrWhiteSpace($AssessorName)) { $runnerArgs['AssessorName'] = $AssessorName }
if (-not [string]::IsNullOrWhiteSpace($ReportTitle)) { $runnerArgs['ReportTitle'] = $ReportTitle }
if (-not [string]::IsNullOrWhiteSpace($LogoPath)) { $runnerArgs['LogoPath'] = $LogoPath }

$runStart = Get-Date
Write-Host ''
Write-Host 'Running audit...' -ForegroundColor Cyan
Write-Progress -Activity 'AuditRunner' -Status 'Evaluating checks...'
try {
    & $runnerPath @runnerArgs
    $runnerExit = $LASTEXITCODE
} catch {
    Write-Progress -Activity 'AuditRunner' -Completed
    Write-Error $_
    exit 1
}
Write-Progress -Activity 'AuditRunner' -Completed
if ($null -ne $runnerExit -and $runnerExit -ne 0) {
    Write-Error "Runner failed with exit code $runnerExit."
    exit $runnerExit
}

$resultCsv = $OutputPath
if ([string]::IsNullOrWhiteSpace($resultCsv)) {
    $inputBase = [System.IO.Path]::GetFileNameWithoutExtension($effectiveInput)
    $matches = Get-ChildItem -LiteralPath $scriptDir -Filter ("{0}_results_*.csv" -f $inputBase) -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($matches -and $matches.Count -gt 0) {
        $fresh = $matches | Where-Object { $_.LastWriteTime -ge $runStart } | Select-Object -First 1
        if ($null -eq $fresh) { $fresh = $matches[0] }
        $resultCsv = $fresh.FullName
    }
}
if ([string]::IsNullOrWhiteSpace($resultCsv) -or -not (Test-Path -LiteralPath $resultCsv)) {
    Write-Error 'Runner finished but no results CSV was found.'
    exit 1
}
$resultCsvFull = Get-FullCliPath -Path $resultCsv

$rows = @(Import-Csv -LiteralPath $resultCsv)
$passCount = 0
$failCount = 0
$manualCount = 0
foreach ($row in $rows) {
    $status = [string]$row.'Pass/Fail/Manual'
    if ([string]::Equals($status.Trim(), 'Pass', [System.StringComparison]::OrdinalIgnoreCase)) {
        $passCount++
    } elseif ([string]::Equals($status.Trim(), 'Fail', [System.StringComparison]::OrdinalIgnoreCase)) {
        $failCount++
    } else {
        $manualCount++
    }
}
$totalCount = $rows.Count

if (-not $Quiet) {
    Write-Host ''
    Write-Host 'Results:' -ForegroundColor Cyan
    foreach ($row in $rows) {
        $status = [string]$row.'Pass/Fail/Manual'
        $label = $status.Trim().ToUpperInvariant()
        $color = 'Yellow'
        if ([string]::Equals($status.Trim(), 'Pass', [System.StringComparison]::OrdinalIgnoreCase)) {
            $color = 'Green'
        } elseif ([string]::Equals($status.Trim(), 'Fail', [System.StringComparison]::OrdinalIgnoreCase)) {
            $color = 'Red'
        }
        Write-Host ("  [{0}] {1}" -f $label, $row.'CHECK') -ForegroundColor $color
    }
}

Write-Host ''
Write-Host 'Summary:' -ForegroundColor Cyan
Write-Host ("  PASS:   {0}" -f $passCount) -ForegroundColor Green
Write-Host ("  FAIL:   {0}" -f $failCount) -ForegroundColor Red
Write-Host ("  MANUAL: {0}" -f $manualCount) -ForegroundColor Yellow
Write-Host ("  TOTAL:  {0}" -f $totalCount)
Write-Host ("  Results: {0}" -f $resultCsvFull) -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    Write-Host ("  Report:  {0}" -f (Get-FullCliPath -Path $HtmlPath)) -ForegroundColor Cyan
}
if (-not $Quiet) {
    Write-Host 'Hints: q quits the picker | -Quiet summary only | -ShowMatrix support matrix | -Help usage' -ForegroundColor DarkGray
}

exit 0
