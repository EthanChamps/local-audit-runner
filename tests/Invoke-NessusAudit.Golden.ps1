$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NessusAudit.ps1'
$source = Get-Content -LiteralPath $runnerPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $source,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw ($parseErrors.Message -join [Environment]::NewLine)
}

foreach ($functionAst in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)) {
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Actual -ne $Expected) {
        throw "$Message Expected <$Expected>, got <$Actual>."
    }
}

function Assert-True {
    param(
        $Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Get-GoldenRow {
    param(
        [array]$Rows,
        [Parameter(Mandatory)][string]$Id
    )
    $match = @($Rows | Where-Object { $_.Id -eq $Id })
    if ($match.Count -ne 1) {
        throw "Expected exactly one row with Id '$Id', found $($match.Count)."
    }
    return $match[0]
}

$fixturePath = Join-Path $PSScriptRoot 'fixtures/coverage.audit'
$rows = @(ConvertFrom-NessusAuditFile -Path $fixturePath)

Assert-Equal $rows.Count 14 'Fixture must produce exactly 14 check rows.'

$unnumbered = @($rows | Where-Object { $_.Id -like 'audit-*' })
Assert-Equal $unnumbered.Count 0 'Numbered descriptions must keep their IDs.'

foreach ($id in @('1.1', '1.2', '1.3', '1.4', '2.1', '2.2', '3.1', '4.1', '5.1', '5.2', '6.1', '7.1', '7.2', '9.9')) {
    Assert-True (@($rows | Where-Object { $_.Id -eq $id }).Count -eq 1) "Row Id '$id' must exist exactly once."
}

Assert-True (@($rows | Where-Object { $_.Title -match 'Windows 11 is installed' }).Count -eq 0) 'Gating item must be skipped.'

Assert-Equal (Get-GoldenRow $rows '1.1').Expected 'ExampleDefault' 'Variable @EXAMPLE_VALUE@ must resolve.'
Assert-Equal (Get-GoldenRow $rows '1.2').Method 'Registry' 'GUID registry must map to Registry.'
Assert-Equal (Get-GoldenRow $rows '1.3').Method 'Registry' 'Banner check must map to Registry.'
Assert-Equal (Get-GoldenRow $rows '1.4').Method 'Registry' 'Reg check must map to Registry.'
Assert-Equal (Get-GoldenRow $rows '2.1').Target 'MinimumPasswordLength' 'Password policy target mismatch.'
Assert-Equal (Get-GoldenRow $rows '2.2').Target 'LockoutBadCount' 'Lockout policy target mismatch.'
Assert-Equal (Get-GoldenRow $rows '3.1').Method 'UserRight' 'User rights must map to UserRight.'
Assert-Equal (Get-GoldenRow $rows '4.1').Method 'AuditPolicy' 'Audit policy must map to AuditPolicy.'
Assert-Equal (Get-GoldenRow $rows '5.1').Operator 'Disabled' 'Check account Disabled mismatch.'
Assert-Equal (Get-GoldenRow $rows '5.2').Operator 'DisabledOrNotInstalled' 'Service Disabled mismatch.'
Assert-Equal (Get-GoldenRow $rows '6.1').Method 'PowerShell' 'Powershell must map to PowerShell.'

$rightAlternatives = @(ConvertFrom-EncodedAlternatives (Get-GoldenRow $rows '3.1').ExpectedData)
Assert-Equal $rightAlternatives.Count 2 'User-right A || B must decode to two alternatives.'

$unknownOne = Get-GoldenRow $rows '7.1'
Assert-Equal $unknownOne.Method 'Manual' 'Unknown type FOO_NEW_TYPE_1 must be Manual.'
Assert-True ($unknownOne.ManualReason -match 'FOO_NEW_TYPE_1') 'Manual reason must name FOO_NEW_TYPE_1.'
$unknownTwo = Get-GoldenRow $rows '7.2'
Assert-Equal $unknownTwo.Method 'Manual' 'Unknown type FOO_NEW_TYPE_2 must be Manual.'
Assert-True ($unknownTwo.ManualReason -match 'FOO_NEW_TYPE_2') 'Manual reason must name FOO_NEW_TYPE_2.'
$manualRows = @($rows | Where-Object { $_.Method -eq 'Manual' })
Assert-Equal $manualRows.Count 2 'Exactly the two unknown types must be Manual.'

$combined = Get-GoldenRow $rows '9.9'
Assert-Equal $combined.Method 'Registry' 'Combined condition must be Registry.'
Assert-Equal $combined.Operator 'AllMatch' 'Combined condition must use AllMatch.'
Assert-Equal $combined.SourceType 'IF_CONDITION' 'Combined condition source type mismatch.'
Assert-Equal $combined.Title 'Example combined condition' 'Combined condition title mismatch.'

Write-Output "All Invoke-NessusAudit golden tests passed ($($rows.Count) rows, $($manualRows.Count) Manual)."
