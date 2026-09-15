<#
.SYNOPSIS
    Support-matrix extractor / drift detector for the two AuditRunner audit runners.

.DESCRIPTION
    The Windows runner (Invoke-AuditRunner.ps1, function Convert-AuditFieldsToCheck)
    and the Unix runner (audit-runner.sh, function emit()) are independent
    implementations that share one CSV format. Each one only understands a fixed
    set of Nessus audit item types / match patterns; everything else falls back
    to Manual.

    This script prints that supported set as a markdown table
    (Runner | Match pattern/sourceType | Method | Fallback) WITHOUT executing
    any audit. The Windows file is parsed with the PowerShell AST parser and the
    shell file is scanned with regex, but the table itself is hardcoded data so
    its shape cannot silently change when a runner is edited.

    DRIFT DETECTION (the point of this script): every hardcoded pattern is
    verified to still exist literally in its runner source file, and the type
    match expressions actually present in the sources are extracted and compared
    against the hardcoded list. If a runner was updated for a newer Nessus
    version (type added, renamed, or removed) without updating this matrix, the
    script writes the offending pattern to stderr and exits with code 2.
    Run it after touching either runner, or whenever the runners appear to
    diverge from each other.

.EXIT CODES
    0 = matrix printed, no drift.
    2 = drift detected (message on stderr names the missing/unexpected pattern),
        a runner file is missing, or a runner file no longer parses.
#>

$ErrorActionPreference = 'Stop'

function Get-MatrixScriptDirectory {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($MyInvocation.MyCommand.Path) { return (Split-Path -Parent $MyInvocation.MyCommand.Path) }
    return (Get-Location).Path
}

function Exit-Drift {
    param([Parameter(Mandatory)][string]$Message)
    [Console]::Error.WriteLine("DRIFT: $Message")
    exit 2
}

$repoRoot = Split-Path -Parent (Get-MatrixScriptDirectory)
$windowsPath = Join-Path $repoRoot 'Invoke-AuditRunner.ps1'
$unixPath = Join-Path $repoRoot 'audit-runner.sh'

if (-not (Test-Path -LiteralPath $windowsPath)) {
    Exit-Drift "Windows runner not found at $windowsPath."
}
if (-not (Test-Path -LiteralPath $unixPath)) {
    Exit-Drift "Unix runner not found at $unixPath."
}

$windowsSource = Get-Content -LiteralPath $windowsPath -Raw
$unixSource = Get-Content -LiteralPath $unixPath -Raw

# --- Parse check 1: Windows runner must still be valid PowerShell (AST, no execution). ---
$tokens = $null
$parseErrors = $null
$winAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $windowsSource,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    Exit-Drift ("Windows runner failed to parse: " + ($parseErrors.Message -join ' | '))
}

$converterAsts = $winAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Convert-AuditFieldsToCheck'
}, $false)
if ($converterAsts.Count -eq 0) {
    Exit-Drift "Function 'Convert-AuditFieldsToCheck' not found in $windowsPath; parser shape changed."
}
$converterBody = $converterAsts[0].Extent.Text

# --- Parse check 2: Unix runner must still contain its emit() parser (regex, no execution). ---
if ($unixSource -notmatch 'function emit\(') {
    Exit-Drift "Function 'emit(' not found in $unixPath; parser shape changed."
}

# --- Hardcoded matrix. Literals[] must each exist verbatim in the runner source. ---
$windowsRows = @(
    [pscustomobject]@{ Match = 'REGISTRY_SETTING';         Literals = @("'REGISTRY_SETTING'");         Method = 'Registry';      Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'GUID_REGISTRY_SETTING';    Literals = @("'GUID_REGISTRY_SETTING'");    Method = 'Registry';      Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'BANNER_CHECK';             Literals = @("'BANNER_CHECK'");             Method = 'Registry';      Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'REG_CHECK';                Literals = @("'REG_CHECK'");                Method = 'Registry';      Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'PASSWORD_POLICY';          Literals = @("'PASSWORD_POLICY'");          Method = 'AccountPolicy'; Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'LOCKOUT_POLICY';           Literals = @("'LOCKOUT_POLICY'");           Method = 'AccountPolicy'; Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'KERBEROS_POLICY';          Literals = @("'KERBEROS_POLICY'");          Method = 'AccountPolicy'; Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'USER_RIGHTS_POLICY';       Literals = @("'USER_RIGHTS_POLICY'");       Method = 'UserRight';     Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'AUDIT_POLICY_SUBCATEGORY'; Literals = @("'AUDIT_POLICY_SUBCATEGORY'"); Method = 'AuditPolicy';   Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'CHECK_ACCOUNT';            Literals = @("'CHECK_ACCOUNT'");            Method = 'LocalAccount';  Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'SERVICE_POLICY';           Literals = @("'SERVICE_POLICY'");           Method = 'Service';       Fallback = 'Manual (expected Disabled passes when service is absent)' }
    [pscustomobject]@{ Match = 'AUDIT_POWERSHELL';         Literals = @("'AUDIT_POWERSHELL'");         Method = 'PowerShell';    Fallback = 'Manual unless -AllowEmbeddedScripts' }
    [pscustomobject]@{ Match = '(else: unsupported type)'; Literals = @('Unsupported Nessus audit item type for this local runner: '); Method = 'Manual'; Fallback = 'Manual (reason in Actual Value; Checklist=0 catalog rows skip evaluation)' }
)

$unixRows = @(
    [pscustomobject]@{ Match = 'typ ~ /^FILE/';                              Literals = @('/^FILE/');                                                                                         Method = 'File';         Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'typ == FILE_CHECK';                          Literals = @('"FILE_CHECK"');                                                                                    Method = 'File';         Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'typ == FILE_CONTENT_CHECK';                  Literals = @('"FILE_CONTENT_CHECK"');                                                                            Method = 'File';         Fallback = 'Manual' }
    [pscustomobject]@{ Match = 'file_mode/mode/owner/group present';         Literals = @('f["file_mode"]', 'FileMetadata');                                                                Method = 'FileMetadata'; Fallback = 'always Manual (details in Actual Value)' }
    [pscustomobject]@{ Match = 'typ ~ /CMD|COMMAND|SHELL/';                  Literals = @('/CMD|COMMAND|SHELL/');                                                                              Method = 'Command';      Fallback = 'Manual unless --allow-command-exec' }
    [pscustomobject]@{ Match = 'f[cmd] / f[command] / f[shell_command]';     Literals = @('f["cmd"]', 'f["command"]', 'f["shell_command"]');                                                   Method = 'Command';      Fallback = 'Manual unless --allow-command-exec' }
    [pscustomobject]@{ Match = 'typ ~ /PACKAGE/ or f[package]/f[pkg]/f[rpm]'; Literals = @('/PACKAGE/', 'f["package"]', 'f["pkg"]', 'f["rpm"]');                                                Method = 'Package';      Fallback = 'Manual if dpkg-query/rpm missing' }
    [pscustomobject]@{ Match = 'typ ~ /PROCESS/ or f[process]';              Literals = @('/PROCESS/', 'f["process"]');                                                                        Method = 'Process';      Fallback = 'Manual if pgrep missing' }
    [pscustomobject]@{ Match = 'typ ~ /SERVICE/ or f[service]';              Literals = @('/SERVICE/', 'f["service"]');                                                                        Method = 'Service';      Fallback = 'Manual if systemctl missing' }
    [pscustomobject]@{ Match = '(else: unsupported type)';                   Literals = @('Unsupported Nessus audit item type for this local runner: ');                                        Method = 'Manual';       Fallback = 'Manual (reason in Actual Value)' }
)

$knownWindowsTypes = @(
    'REGISTRY_SETTING', 'GUID_REGISTRY_SETTING', 'BANNER_CHECK', 'REG_CHECK',
    'PASSWORD_POLICY', 'LOCKOUT_POLICY', 'KERBEROS_POLICY', 'USER_RIGHTS_POLICY',
    'AUDIT_POLICY_SUBCATEGORY', 'CHECK_ACCOUNT', 'SERVICE_POLICY', 'AUDIT_POWERSHELL'
)
$knownUnixEquals = @('FILE_CHECK', 'FILE_CONTENT_CHECK')
$knownUnixRegexes = @('^FILE', 'CMD|COMMAND|SHELL', 'PACKAGE', 'PROCESS', 'SERVICE')

# --- Drift check A: every hardcoded literal must still exist verbatim in its source. ---
foreach ($row in $windowsRows) {
    foreach ($literal in $row.Literals) {
        if (-not $windowsSource.Contains($literal)) {
            Exit-Drift "Windows pattern '$literal' (matrix entry '$($row.Match)') not found in $windowsPath."
        }
    }
}
foreach ($row in $unixRows) {
    foreach ($literal in $row.Literals) {
        if (-not $unixSource.Contains($literal)) {
            Exit-Drift "Unix pattern '$literal' (matrix entry '$($row.Match)') not found in $unixPath."
        }
    }
}

# --- Drift check B: types matched in the Windows parser must equal the hardcoded list. ---
$foundWindowsTypes = @()
foreach ($m in [regex]::Matches($converterBody, '\$sourceType\s+-eq\s+''([A-Z][A-Z_]+)''')) {
    $foundWindowsTypes += $m.Groups[1].Value
}
foreach ($m in [regex]::Matches($converterBody, '\$sourceType\s+-in\s+@\(([^)]*)\)')) {
    foreach ($q in [regex]::Matches($m.Groups[1].Value, "'([A-Z][A-Z_]+)'")) {
        $foundWindowsTypes += $q.Groups[1].Value
    }
}
$foundWindowsTypes = @($foundWindowsTypes | Sort-Object -Unique)
foreach ($t in $foundWindowsTypes) {
    if ($knownWindowsTypes -notcontains $t) {
        Exit-Drift "Windows runner matches sourceType '$t' which is not in the support matrix; update tools/Get-AuditRunnerMatrix.ps1."
    }
}
foreach ($t in $knownWindowsTypes) {
    if ($foundWindowsTypes -notcontains $t) {
        Exit-Drift "Windows matrix entry '$t' is no longer matched in Convert-AuditFieldsToCheck; update tools/Get-AuditRunnerMatrix.ps1."
    }
}

# --- Drift check C: type patterns matched in the Unix emit() must equal the hardcoded list. ---
$foundUnixEquals = @()
foreach ($m in [regex]::Matches($unixSource, 'typ\s*==\s*"([^"]+)"')) {
    $foundUnixEquals += $m.Groups[1].Value
}
$foundUnixEquals = @($foundUnixEquals | Sort-Object -Unique)
$foundUnixRegexes = @()
foreach ($m in [regex]::Matches($unixSource, 'typ\s*~\s*/([^/]+)/')) {
    $foundUnixRegexes += $m.Groups[1].Value
}
$foundUnixRegexes = @($foundUnixRegexes | Sort-Object -Unique)
foreach ($t in $foundUnixEquals) {
    if ($knownUnixEquals -notcontains $t) {
        Exit-Drift "Unix runner matches type '$t' which is not in the support matrix; update tools/Get-AuditRunnerMatrix.ps1."
    }
}
foreach ($t in $knownUnixEquals) {
    if ($foundUnixEquals -notcontains $t) {
        Exit-Drift "Unix matrix entry '$t' is no longer matched in emit(); update tools/Get-AuditRunnerMatrix.ps1."
    }
}
foreach ($t in $foundUnixRegexes) {
    if ($knownUnixRegexes -notcontains $t) {
        Exit-Drift "Unix runner matches pattern '/$t/' which is not in the support matrix; update tools/Get-AuditRunnerMatrix.ps1."
    }
}
foreach ($t in $knownUnixRegexes) {
    if ($foundUnixRegexes -notcontains $t) {
        Exit-Drift "Unix matrix entry '/$t/' is no longer matched in emit(); update tools/Get-AuditRunnerMatrix.ps1."
    }
}

# --- Output: simple markdown table on stdout. ---
function Format-MatrixCell {
    param([string]$Value)
    return ($Value -replace '\|', '\|')
}

Write-Output '| Runner | Match pattern/sourceType | Method | Fallback |'
Write-Output '| --- | --- | --- | --- |'
foreach ($row in $windowsRows) {
    Write-Output ('| Windows | {0} | {1} | {2} |' -f (Format-MatrixCell $row.Match), (Format-MatrixCell $row.Method), (Format-MatrixCell $row.Fallback))
}
foreach ($row in $unixRows) {
    Write-Output ('| Unix | {0} | {1} | {2} |' -f (Format-MatrixCell $row.Match), (Format-MatrixCell $row.Method), (Format-MatrixCell $row.Fallback))
}

exit 0
