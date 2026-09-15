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

$orAlternatives = Split-AuditOrExpression '"Success" || "Success and Failure"'
Assert-Equal $orAlternatives.Count 2 'OR expressions must remain separate alternatives.'
Assert-Equal $orAlternatives[0].Count 1 'The first OR alternative must contain one item.'

$andAlternatives = Split-AuditOrExpression '"LOCAL SERVICE" && "NETWORK SERVICE"'
Assert-Equal $andAlternatives.Count 1 'AND expressions must remain one alternative.'
Assert-Equal $andAlternatives[0].Count 2 'An AND alternative must retain all required items.'

$legacyEncoded = 'IlN1Y2Nlc3MiIHx8ICJTdWNjZXNzIGFuZCBGYWlsdXJlIg=='
$legacyAlternatives = @(ConvertFrom-EncodedAlternatives $legacyEncoded)
Assert-Equal $legacyAlternatives.Count 2 'Legacy OR expressions must decode as separate alternatives.'

$auditFields = @{
    type = 'AUDIT_POLICY_SUBCATEGORY'
    description = "6.7 Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    value_data = '"Success" || "Success and Failure"'
    audit_policy_subcategory = 'Authentication Policy Change'
}
$auditCheck = Convert-AuditFieldsToCheck -Fields $auditFields -Variables @{} -Index 1
$auditAlternatives = @(ConvertFrom-EncodedAlternatives $auditCheck.ExpectedData)
Assert-Equal $auditAlternatives.Count 2 'Audit policy OR values must serialize as separate alternatives.'

$rightFields = @{
    type = 'USER_RIGHTS_POLICY'
    description = "90.32 Ensure 'Replace Process Level Token' is set correctly"
    value_data = '"LOCAL SERVICE" && "NETWORK SERVICE"'
    right_type = 'SeAssignPrimaryTokenPrivilege'
}
$rightCheck = Convert-AuditFieldsToCheck -Fields $rightFields -Variables @{} -Index 2
$rightAlternatives = @(ConvertFrom-EncodedAlternatives $rightCheck.ExpectedData)
Assert-Equal $rightAlternatives.Count 1 'User-right AND values must serialize as one alternative.'
Assert-Equal $rightAlternatives[0].Items.Count 2 'User-right AND values must retain both principals.'

$servicePrincipals = ConvertTo-EncodedAlternatives (
    Split-AuditOrExpression '"LOCAL SERVICE" && "NETWORK SERVICE" && "PrintSpoolerService"'
)
$principalMatch = Test-PrincipalAlternatives `
    -ActualRaw 'NT AUTHORITY\LOCAL SERVICE,NT AUTHORITY\NETWORK SERVICE,RESTRICTED SERVICES\PrintSpoolerService' `
    -EncodedAlternatives $servicePrincipals `
    -Operator 'ExactAlternatives'
Assert-Equal $principalMatch $true 'Service principal namespaces must normalize consistently.'

$serviceFields = @{
    type = 'SERVICE_POLICY'
    description = "82.5 Ensure 'GameInput Service' is set to 'Disabled'"
    service_name = 'GameInputSvc'
    value_data = 'Disabled'
}
$serviceCheck = Convert-AuditFieldsToCheck -Fields $serviceFields -Variables @{} -Index 3
Assert-Equal $serviceCheck.Method 'Service' 'SERVICE_POLICY must produce an executable service check.'
Assert-Equal $serviceCheck.Operator 'DisabledOrNotInstalled' 'Disabled services may also be absent.'

Assert-Equal (Test-ScalarValue -Actual '10' -Operator 'Equals' -Expected '1') $false 'Equals must not prefix-match numbers.'
Assert-Equal (Test-ScalarValue -Actual '10' -Operator 'Equals' -Expected '10') $true 'Equals must match identical numbers.'
Assert-Equal (Test-ScalarValue -Actual '14' -Operator 'Equals' -Expected '14 days') $false 'Equals must not match trailing text.'
Assert-Equal (Test-ScalarValue -Actual '0x10' -Operator 'Equals' -Expected '16') $true 'Equals must normalize hex.'
Assert-Equal (Test-ScalarValue -Actual 'Enabled' -Operator 'Equals' -Expected '1') $true 'Equals must normalize boolean text.'

Assert-Equal (Test-ScalarValue -Actual 'a' -Operator 'NotEqual' -Expected 'b') $true 'NotEqual must pass on difference.'
Assert-Equal (Test-ScalarValue -Actual 'a' -Operator 'NotEqual' -Expected 'A') $false 'NotEqual must be case-insensitive.'

Assert-Equal (Test-ScalarValue -Actual 'Example value 123' -Operator 'Regex' -Expected 'value \d+') $true 'Regex must match a substring.'
Assert-Equal (Test-ScalarValue -Actual 'abc' -Operator 'Regex' -Expected '^\d+$') $false 'Regex must fail a non-match.'
Assert-Equal (Test-ScalarValue -Actual $null -Operator 'Regex' -Expected 'x') $false 'Regex on a missing value must fail.'
Assert-Equal (Test-ScalarValue -Actual $null -Operator 'NotRegex' -Expected 'x') $true 'NotRegex on a missing value must pass.'
Assert-Equal (Test-ScalarValue -Actual 'abc' -Operator 'NotRegex' -Expected '^\d+$') $true 'NotRegex must pass a non-match.'
Assert-Equal (Test-ScalarValue -Actual '123' -Operator 'NotRegex' -Expected '^\d+$') $false 'NotRegex must fail a match.'

Assert-Equal (Test-ScalarValue -Actual '1' -Operator 'Range' -Expected '[1..10]') $true 'Range must include the lower boundary.'
Assert-Equal (Test-ScalarValue -Actual '10' -Operator 'Range' -Expected '[1..10]') $true 'Range must include the upper boundary.'
Assert-Equal (Test-ScalarValue -Actual '0' -Operator 'Range' -Expected '[1..10]') $false 'Range must exclude below-minimum.'
Assert-Equal (Test-ScalarValue -Actual '11' -Operator 'Range' -Expected '[1..10]') $false 'Range must exclude above-maximum.'
Assert-Equal (Test-ScalarValue -Actual '5' -Operator 'Range' -Expected 'MIN..MAX') $true 'Range must support bare MIN..MAX.'
Assert-Equal (Test-ScalarValue -Actual 'abc' -Operator 'Range' -Expected '[1..10]') $false 'Range must fail non-numeric actuals.'

Assert-Equal (Test-ScalarValue -Actual $null -Operator 'NotExists' -Expected '') $true 'NotExists must pass on missing values.'
Assert-Equal (Test-ScalarValue -Actual '' -Operator 'NotExists' -Expected '') $false 'NotExists must fail on empty strings.'

$mustNotExist = ConvertTo-AuditOperator -ValueData 'anything' -CheckType '' -RegOption 'MUST_NOT_EXIST'
Assert-Equal $mustNotExist.Operator 'NotExists' 'MUST_NOT_EXIST must map to NotExists.'
Assert-Equal (ConvertTo-AuditOperator -ValueData 'x' -CheckType 'CHECK_REGEX' -RegOption '').Operator 'Regex' 'CHECK_REGEX must map to Regex.'
Assert-Equal (ConvertTo-AuditOperator -ValueData 'x' -CheckType 'CHECK_NOT_REGEX' -RegOption '').Operator 'NotRegex' 'CHECK_NOT_REGEX must map to NotRegex.'
Assert-Equal (ConvertTo-AuditOperator -ValueData 'x' -CheckType 'CHECK_NOT_EQUAL' -RegOption '').Operator 'NotEqual' 'CHECK_NOT_EQUAL must map to NotEqual.'
Assert-Equal (ConvertTo-AuditOperator -ValueData '[1..10]' -CheckType '' -RegOption '').Operator 'Range' 'Bracket ranges must map to Range.'

$orEncoded = ConvertTo-EncodedAlternatives (Split-AuditOrExpression '"A" || "B"')
Assert-Equal (Test-ScalarValue -Actual @('A') -Operator 'In' -Expected 'x' -ExpectedData $orEncoded) $true 'In must pass one matching OR branch.'
Assert-Equal (Test-ScalarValue -Actual @('A', 'B') -Operator 'In' -Expected 'x' -ExpectedData $orEncoded) $false 'In must reject the union of OR branches.'
$andEncoded = ConvertTo-EncodedAlternatives (Split-AuditOrExpression '"A" && "B"')
Assert-Equal (Test-ScalarValue -Actual @('A', 'B') -Operator 'In' -Expected 'x' -ExpectedData $andEncoded) $true 'In must pass a full AND alternative.'
Assert-Equal (Test-ScalarValue -Actual @('A') -Operator 'In' -Expected 'x' -ExpectedData $andEncoded) $false 'In must reject a partial AND alternative.'
Assert-Equal (Test-ScalarValue -Actual @('A', 'B', 'C') -Operator 'In' -Expected 'x' -ExpectedData $andEncoded) $false 'In must reject extras.'
Assert-Equal (Test-ScalarValue -Actual @('A', 'B', 'C') -Operator 'ContainsAlternatives' -Expected 'x' -ExpectedData $andEncoded) $true 'ContainsAlternatives must allow extras.'
Assert-Equal (Test-ScalarValue -Actual 'A,B' -Operator 'In' -Expected 'x' -ExpectedData $andEncoded) $false 'In must not split string actuals on commas.'

$roundTrip = @(ConvertFrom-EncodedAlternatives (ConvertTo-EncodedAlternatives (Split-AuditOrExpression '"A" || "B" && "C"')))
Assert-Equal $roundTrip.Count 2 'OR round-trip must preserve alternative count.'
Assert-Equal $roundTrip[0].Items.Count 1 'First OR branch must keep one item.'
Assert-Equal $roundTrip[1].Items.Count 2 'AND branch must keep both items.'

$emptyEncoded = ConvertTo-EncodedAlternatives @(@(''))
Assert-Equal $emptyEncoded '~' 'Empty strings must encode as tilde.'
$emptyDecoded = @(ConvertFrom-EncodedAlternatives '~')
Assert-Equal $emptyDecoded.Count 1 'Tilde must decode to one alternative.'
Assert-Equal $emptyDecoded[0].Items.Count 1 'Tilde alternative must hold one item.'
Assert-Equal $emptyDecoded[0].Items[0] '' 'Tilde must decode back to empty string.'

$futureFields = @{ type = 'FOO_FUTURE_TYPE'; description = '99.1 Example future type' }
$futureCheck = Convert-AuditFieldsToCheck -Fields $futureFields -Variables @{} -Index 1
Assert-Equal $futureCheck.Method 'Manual' 'Unknown source types must be Manual.'
Assert-True ($futureCheck.ManualReason -match 'FOO_FUTURE_TYPE') 'Manual reason must name the unknown type.'

$bogusResult = Invoke-NessusCheck (New-AuditCheckRow -Id 'x' -Title 't' -Method 'Bogus')
Assert-True ($null -eq $bogusResult.Pass) 'Unknown methods must fail closed to Manual.'
Assert-Equal $bogusResult.Actual 'Manual review required' 'Unknown methods need a default Manual reason.'

$kerberosFields = @{ type = 'KERBEROS_POLICY'; description = '9.1 Example kerberos'; kerberos_policy = 'MaxTicketAge'; value_data = '10' }
$kerberosCheck = Convert-AuditFieldsToCheck -Fields $kerberosFields -Variables @{} -Index 1
Assert-Equal $kerberosCheck.Method 'AccountPolicy' 'KERBEROS_POLICY must map to AccountPolicy.'
Assert-Equal $kerberosCheck.Target 'MaxTicketAge' 'Kerberos policy target mismatch.'

$unknownKerberosFields = @{ type = 'KERBEROS_POLICY'; description = '9.2 Example unknown kerberos'; kerberos_policy = 'NopeUnknown'; value_data = '10' }
$unknownKerberosCheck = Convert-AuditFieldsToCheck -Fields $unknownKerberosFields -Variables @{} -Index 2
Assert-Equal $unknownKerberosCheck.Method 'Manual' 'Unknown kerberos keys must be Manual.'

function New-ChecklistProbe {
    param([string]$ChecklistValue, [switch]$OmitColumn)
    $probe = New-AuditCheckRow -Id 'x' -Title 't' -Method 'Registry' -Expected 'e'
    if (-not $OmitColumn) {
        $probe | Add-Member -NotePropertyName 'Checklist' -NotePropertyValue $ChecklistValue -Force
    }
    return $probe
}

Assert-True (Test-ChecklistExcluded (New-ChecklistProbe -ChecklistValue '0')) 'Checklist=0 must be excluded.'
Assert-True (Test-ChecklistExcluded (New-ChecklistProbe -ChecklistValue ' 0 ')) 'Checklist=0 must trim before compare.'
Assert-True (-not (Test-ChecklistExcluded (New-ChecklistProbe -ChecklistValue '1'))) 'Checklist=1 must evaluate.'
Assert-True (-not (Test-ChecklistExcluded (New-ChecklistProbe -ChecklistValue '00'))) 'Checklist=00 must not ordinal-match 0.'
Assert-True (-not (Test-ChecklistExcluded (New-ChecklistProbe -ChecklistValue ''))) 'Empty Checklist must evaluate.'
Assert-True (-not (Test-ChecklistExcluded (New-ChecklistProbe -OmitColumn))) 'Missing Checklist column must evaluate.'

Write-Output 'All Invoke-NessusAudit regression tests passed.'
