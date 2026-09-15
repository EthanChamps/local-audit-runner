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
    [string]$LogoPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SecurityPolicy = $null
$script:AuditPolicy = $null
$script:AllowEmbeddedScripts = [bool]$AllowEmbeddedScripts

function Get-ObjectPropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AuditField {
    param(
        [hashtable]$Fields,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Fields.ContainsKey($Name)) { return [string]$Fields[$Name] }
    return ''
}

function ConvertTo-CsvSafeJson {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ($Value | ConvertTo-Json -Compress -Depth 12)
}

function Unquote-AuditValue {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $text = $Value.Trim()
    if ($text.Length -lt 2) { return $text }
    $quote = $text[0]
    if ($quote -ne '"' -and $quote -ne "'") { return $text }

    $chars = New-Object System.Collections.Generic.List[char]
    for ($i = 1; $i -lt $text.Length; $i++) {
        $ch = $text[$i]
        if ($ch -eq '\' -and ($i + 1) -lt $text.Length -and $text[$i + 1] -eq $quote) {
            $chars.Add($quote)
            $i++
            continue
        }
        if ($ch -eq $quote) {
            if ([string]::IsNullOrWhiteSpace($text.Substring($i + 1))) {
                return (-join $chars.ToArray())
            }
            return $text
        }
        $chars.Add($ch)
    }
    return $text
}

function Read-AuditVariables {
    param([string]$Text)

    $variables = @{}
    foreach ($match in [regex]::Matches($Text, '<variable>\s*(.*?)\s*</variable>', 'Singleline')) {
        $block = $match.Groups[1].Value
        $nameMatch = [regex]::Match($block, '<name>(.*?)</name>', 'Singleline')
        $defaultMatch = [regex]::Match($block, '<default>(.*?)</default>', 'Singleline')
        if ($nameMatch.Success -and $defaultMatch.Success) {
            $variables[$nameMatch.Groups[1].Value.Trim()] = $defaultMatch.Groups[1].Value.Trim()
        }
    }
    return $variables
}

function Resolve-AuditValue {
    param(
        [string]$Value,
        [hashtable]$Variables
    )

    $text = Unquote-AuditValue $Value
    if ($text -match '^@([A-Za-z0-9_]+)@$' -and $Variables.ContainsKey($Matches[1])) {
        return $Variables[$Matches[1]]
    }
    return $text
}

function ConvertTo-EncodedAlternatives {
    param([array]$Alternatives)

    $encodedAlternatives = New-Object System.Collections.Generic.List[string]
    foreach ($alternative in $Alternatives) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($item in @($alternative)) {
            if ($item -eq '') {
                $items.Add('~')
            } else {
                $items.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$item)))
            }
        }
        $encodedAlternatives.Add(($items.ToArray() -join ','))
    }
    return ($encodedAlternatives.ToArray() -join ';')
}

function Split-AuditOrExpression {
    param([string]$Expression)

    $alternatives = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Expression) { $Expression = '' }
    $value = $Expression.Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq '""' -or $value -eq "''") {
        $alternatives.Add(@(''))
        return @($alternatives.ToArray())
    }

    $outerParts = $value -split '\s+\|\|\s+'
    foreach ($outerPart in $outerParts) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($innerPart in ($outerPart -split '\s+&&\s+')) {
            $clean = (Unquote-AuditValue ($innerPart.Trim([char[]]@('(', ')', ' ')))).Trim()
            if ($clean -ne '') { $items.Add($clean) }
        }
        if ($items.Count -eq 0) { $items.Add('') }
        $alternatives.Add([string[]]$items.ToArray())
    }
    # Preserve each alternative as its own string array. Without the unary comma,
    # PowerShell can unwrap the nested arrays and serialize the whole OR expression
    # as one encoded value.
    return ,$alternatives.ToArray()
}

function Get-AuditDescriptionParts {
    param([string]$Description)

    $clean = Unquote-AuditValue $Description
    if ($clean -match '^([0-9]+(?:\.[0-9]+)*)\s+(?:\(L[0-9]+\)\s+)?(.*)$') {
        return [pscustomobject]@{ Id = $Matches[1]; Title = $Matches[2].Trim() }
    }
    return [pscustomobject]@{ Id = ''; Title = $clean }
}

function ConvertTo-AuditOperator {
    param(
        [string]$ValueData,
        [string]$CheckType,
        [string]$RegOption
    )

    $expected = Unquote-AuditValue $ValueData
    if ($RegOption -eq 'MUST_NOT_EXIST') {
        return [pscustomobject]@{ Operator = 'NotExists'; Expected = 'Must not exist'; ExpectedData = '' }
    }
    switch ($CheckType) {
        'CHECK_REGEX' { return [pscustomobject]@{ Operator = 'Regex'; Expected = $expected; ExpectedData = $expected } }
        'CHECK_NOT_REGEX' { return [pscustomobject]@{ Operator = 'NotRegex'; Expected = $expected; ExpectedData = $expected } }
        'CHECK_NOT_EQUAL' { return [pscustomobject]@{ Operator = 'NotEqual'; Expected = $expected; ExpectedData = $expected } }
    }
    if ($expected -match '^\[\s*(MIN|\d+)\s*\.\.\s*(MAX|\d+)\s*\]$') {
        return [pscustomobject]@{ Operator = 'Range'; Expected = $expected; ExpectedData = '' }
    }
    if ($ValueData -match '\|\|') {
        $alternatives = Split-AuditOrExpression $ValueData
        $display = (($alternatives | ForEach-Object { (@($_) -join ' AND ') }) -join ' OR ')
        return [pscustomobject]@{ Operator = 'In'; Expected = $display; ExpectedData = (ConvertTo-EncodedAlternatives $alternatives) }
    }
    return [pscustomobject]@{ Operator = 'Equals'; Expected = $expected; ExpectedData = $expected }
}

function New-AuditCheckRow {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Method,
        [string]$Target = '',
        [string]$Operator = '',
        [string]$Expected = '',
        [string]$ExpectedData = '',
        [string]$ExpectedJson = '',
        [string]$TargetsJson = '',
        [string]$ValueType = '',
        [string]$SourceType = '',
        [string]$RegOption = '',
        [string]$CheckType = '',
        [string]$ManualReason = ''
    )

    [pscustomobject]@{
        Id = $Id
        Title = $Title
        Method = $Method
        Target = $Target
        Operator = $Operator
        Expected = $Expected
        ExpectedData = $ExpectedData
        ExpectedJson = $ExpectedJson
        TargetsJson = $TargetsJson
        ValueType = $ValueType
        SourceType = $SourceType
        RegOption = $RegOption
        CheckType = $CheckType
        ManualReason = $ManualReason
    }
}

function Convert-AuditFieldsToCheck {
    param(
        [hashtable]$Fields,
        [hashtable]$Variables,
        [int]$Index
    )

    $sourceType = Get-AuditField -Fields $Fields -Name 'type'
    $description = Get-AuditField -Fields $Fields -Name 'description'
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Audit item $Index"
    }
    $parts = Get-AuditDescriptionParts $description
    $id = if ([string]::IsNullOrWhiteSpace($parts.Id)) { "audit-$('{0:d4}' -f $Index)" } else { $parts.Id }
    $title = $parts.Title
    $valueData = Resolve-AuditValue -Value (Get-AuditField -Fields $Fields -Name 'value_data') -Variables $Variables
    $checkType = Get-AuditField -Fields $Fields -Name 'check_type'
    $regOption = Get-AuditField -Fields $Fields -Name 'reg_option'
    $valueType = Get-AuditField -Fields $Fields -Name 'value_type'

    if ($sourceType -in @('REGISTRY_SETTING', 'GUID_REGISTRY_SETTING', 'BANNER_CHECK')) {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        $target = [ordered]@{
            Path = Get-AuditField -Fields $Fields -Name 'reg_key'
            Name = Get-AuditField -Fields $Fields -Name 'reg_item'
            Operator = $op.Operator
            Expected = $op.Expected
            ExpectedData = $op.ExpectedData
            RegOption = $regOption
        }
        $guidRegKey = Get-AuditField -Fields $Fields -Name 'guid_reg_key'
        if (-not [string]::IsNullOrWhiteSpace($guidRegKey)) {
            $target.GuidRegKey = $guidRegKey
        }
        $targetText = "{0}\{1}" -f $target.Path, $target.Name
        return New-AuditCheckRow -Id $id -Title $title -Method 'Registry' -Target $targetText -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -TargetsJson (ConvertTo-CsvSafeJson @($target)) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'REG_CHECK') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        $path = Unquote-AuditValue $valueData
        $target = [ordered]@{
            Path = $path
            Name = Get-AuditField -Fields $Fields -Name 'key_item'
            Operator = $op.Operator
            Expected = $op.Expected
            ExpectedData = $op.ExpectedData
            RegOption = $regOption
        }
        $targetText = "{0}\{1}" -f $target.Path, $target.Name
        return New-AuditCheckRow -Id $id -Title $title -Method 'Registry' -Target $targetText -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -TargetsJson (ConvertTo-CsvSafeJson @($target)) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -in @('PASSWORD_POLICY', 'LOCKOUT_POLICY', 'KERBEROS_POLICY')) {
        $policyName = (Get-AuditField -Fields $Fields -Name 'password_policy') + (Get-AuditField -Fields $Fields -Name 'lockout_policy') + (Get-AuditField -Fields $Fields -Name 'kerberos_policy')
        $policyTarget = switch ($policyName) {
            'ENFORCE_PASSWORD_HISTORY' { 'PasswordHistorySize' }
            'MAXIMUM_PASSWORD_AGE' { 'MaximumPasswordAge' }
            'MINIMUM_PASSWORD_AGE' { 'MinimumPasswordAge' }
            'MINIMUM_PASSWORD_LENGTH' { 'MinimumPasswordLength' }
            'COMPLEXITY_REQUIREMENTS' { 'PasswordComplexity' }
            'REVERSIBLE_ENCRYPTION' { 'ClearTextPassword' }
            'ALLOW_ADMINISTRATOR_ACCOUNT_LOCKOUT' { 'AllowAdministratorLockout' }
            'LOCKOUT_DURATION' { 'LockoutDuration' }
            'LOCKOUT_THRESHOLD' { 'LockoutBadCount' }
            'RESET_LOCKOUT_COUNTER' { 'ResetLockoutCount' }
            'TicketValidateClient' { 'TicketValidateClient' }
            'MaxServiceAge' { 'MaxServiceAge' }
            'MaxTicketAge' { 'MaxTicketAge' }
            'MaxRenewAge' { 'MaxRenewAge' }
            'MaxClockSkew' { 'MaxClockSkew' }
            'ForceLogoffWhenHourExpire' { 'ForceLogoffWhenHourExpire' }
            default { '' }
        }
        if (-not [string]::IsNullOrWhiteSpace($policyTarget)) {
            $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
            return New-AuditCheckRow -Id $id -Title $title -Method 'AccountPolicy' -Target $policyTarget -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
        }
    }

    if ($sourceType -eq 'USER_RIGHTS_POLICY') {
        $alternatives = Split-AuditOrExpression (Get-AuditField -Fields $Fields -Name 'value_data')
        $operator = if ($checkType -eq 'CHECK_SUPERSET') { 'ContainsAlternatives' } else { 'ExactAlternatives' }
        $display = (($alternatives | ForEach-Object {
            $items = @($_)
            if ($items.Count -eq 1 -and $items[0] -eq '') { 'No One' } else { $items -join ' AND ' }
        }) -join ' OR ')
        return New-AuditCheckRow -Id $id -Title $title -Method 'UserRight' -Target (Get-AuditField -Fields $Fields -Name 'right_type') -Operator $operator -Expected $display -ExpectedData (ConvertTo-EncodedAlternatives $alternatives) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'AUDIT_POLICY_SUBCATEGORY') {
        $alternatives = New-Object System.Collections.Generic.List[object]
        foreach ($alternative in (Split-AuditOrExpression $valueData)) {
            $alternatives.Add([string[]]@($alternative))
        }

        if ($alternatives.Count -eq 1 -and $title -match '\binclude\b') {
            $requiredTokens = @()
            foreach ($item in $alternatives[0]) {
                $requiredTokens += ConvertTo-AuditSettingTokens $item
            }
            $requiredTokens = @($requiredTokens | Select-Object -Unique)
            if ($requiredTokens.Count -eq 1) {
                $alternatives.Add([string[]]@('Success', 'Failure'))
            }
        }
        $display = (($alternatives.ToArray() | ForEach-Object { (@($_) -join ' and ') }) -join ' OR ')
        return New-AuditCheckRow -Id $id -Title $title -Method 'AuditPolicy' -Target (Get-AuditField -Fields $Fields -Name 'audit_policy_subcategory') -Operator 'ExactAlternatives' -Expected $display -ExpectedData (ConvertTo-EncodedAlternatives ($alternatives.ToArray())) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'CHECK_ACCOUNT') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        if ((Unquote-AuditValue $valueData) -eq 'Disabled') {
            $op = [pscustomobject]@{ Operator = 'Disabled'; Expected = 'Disabled'; ExpectedData = '' }
        }
        return New-AuditCheckRow -Id $id -Title $title -Method 'LocalAccount' -Target (Get-AuditField -Fields $Fields -Name 'account_type') -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'SERVICE_POLICY') {
        $serviceName = Get-AuditField -Fields $Fields -Name 'service_name'
        if ([string]::IsNullOrWhiteSpace($serviceName)) {
            $serviceName = Get-AuditField -Fields $Fields -Name 'service'
        }
        if ([string]::IsNullOrWhiteSpace($serviceName)) {
            return New-AuditCheckRow -Id $id -Title $title -Method 'Manual' -Expected 'Manual review required' -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType -ManualReason 'SERVICE_POLICY is missing service_name.'
        }

        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        if ((Unquote-AuditValue $valueData) -ieq 'Disabled') {
            $op = [pscustomobject]@{ Operator = 'DisabledOrNotInstalled'; Expected = 'Disabled'; ExpectedData = '' }
        }
        return New-AuditCheckRow -Id $id -Title $title -Method 'Service' -Target $serviceName -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'AUDIT_POWERSHELL') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        return New-AuditCheckRow -Id $id -Title $title -Method 'PowerShell' -Target (Get-AuditField -Fields $Fields -Name 'powershell_args') -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    return New-AuditCheckRow -Id $id -Title $title -Method 'Manual' -Expected 'Manual review required' -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType -ManualReason "Unsupported Nessus audit item type for this local runner: $sourceType"
}

function Read-AuditCustomItemFields {
    # Read a <custom_item> body starting at the line after the opening tag and return
    # both the parsed field hashtable and the index of the closing </custom_item> line.
    param(
        [string[]]$Lines,
        [int]$Start
    )
    $fields = @{}
    $j = $Start
    while ($j -lt $Lines.Count -and $Lines[$j].Trim() -ne '</custom_item>') {
        if ($Lines[$j] -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s+:\s*(.*?)\s*$') {
            $key = $Matches[1]
            $value = $Matches[2]
            if ($key -eq 'value_data') {
                $fields[$key] = $value.Trim()
            } else {
                $fields[$key] = Unquote-AuditValue $value
            }
        }
        $j++
    }
    return [pscustomobject]@{ Fields = $fields; EndIndex = $j }
}

function New-CombinedConditionCheck {
    # A numbered <report> whose test logic lives in the preceding <condition> (an
    # "<if> recommendation"). Combine the condition's registry items into one check
    # titled by the report's CIS number, instead of leaving each condition item as an
    # unnamed 'audit-####' row.
    param(
        $ReportParts,
        [System.Collections.Generic.List[object]]$ConditionItems,
        [hashtable]$Variables,
        [int]$Index
    )

    $targets = New-Object System.Collections.Generic.List[object]
    $expectedParts = New-Object System.Collections.Generic.List[string]
    foreach ($fields in $ConditionItems) {
        $sub = Convert-AuditFieldsToCheck -Fields $fields -Variables $Variables -Index $Index
        if ($sub.Method -ne 'Registry') { return $null }   # caller falls back to per-item rows
        foreach ($t in @($sub.TargetsJson | ConvertFrom-Json)) {
            $targets.Add($t)
            $expectedParts.Add(('{0} {1} {2}' -f $t.Name, $t.Operator, $t.Expected).Trim())
        }
    }
    if ($targets.Count -eq 0) { return $null }

    return New-AuditCheckRow -Id $ReportParts.Id -Title $ReportParts.Title -Method 'Registry' `
        -Target $ReportParts.Title -Operator 'AllMatch' -Expected (($expectedParts.ToArray()) -join ' AND ') `
        -TargetsJson (ConvertTo-CsvSafeJson @($targets.ToArray())) -SourceType 'IF_CONDITION'
}

function ConvertFrom-NessusAuditFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Audit file not found: $Path"
    }

    $text = Get-Content -LiteralPath $Path -Raw
    $variables = Read-AuditVariables $text
    $lines = $text -split "`r?`n"
    $rows = New-Object System.Collections.Generic.List[object]
    $index = 0

    # Structure-aware walk. Nessus expresses some recommendations as
    # <if><condition>...test items...</condition><then><report>NUMBER</report></then>.
    # The condition items carry no CIS number on their own, so we must title them from
    # the report. Items that sit inside a condition with NO numbered report are pure
    # gates (OS / role detection) and are skipped. Everything else parses as before.
    $stack = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $lines.Count) {
        $t = $lines[$i].Trim()

        if ($t -eq '<if>') {
            $stack.Add([pscustomobject]@{
                ConditionItems     = (New-Object System.Collections.Generic.List[object])
                CollectingCondition = $false
                Emitted            = $false
            })
            $i++; continue
        }
        if ($t -eq '</if>') {
            if ($stack.Count -gt 0) { $stack.RemoveAt($stack.Count - 1) }
            $i++; continue
        }

        $cur = if ($stack.Count -gt 0) { $stack[$stack.Count - 1] } else { $null }

        if ($t -match '^<condition') {
            if ($cur) { $cur.CollectingCondition = $true }
            $i++; continue
        }
        if ($t -eq '</condition>') {
            if ($cur) { $cur.CollectingCondition = $false }
            $i++; continue
        }

        if ($t -match '^<report') {
            $desc = ''
            $j = $i + 1
            while ($j -lt $lines.Count -and $lines[$j].Trim() -ne '</report>') {
                if ($desc -eq '' -and $lines[$j] -match '^\s*description\s*:\s*(.*?)\s*$') {
                    $desc = $Matches[1]
                }
                $j++
            }
            if ($cur -and -not $cur.Emitted -and $desc -ne '') {
                $parts = Get-AuditDescriptionParts $desc
                if (-not [string]::IsNullOrWhiteSpace($parts.Id)) {
                    $index++
                    $combined = New-CombinedConditionCheck -ReportParts $parts -ConditionItems $cur.ConditionItems -Variables $variables -Index $index
                    if ($null -ne $combined) {
                        $rows.Add($combined)
                    } else {
                        foreach ($f in $cur.ConditionItems) {
                            $index++
                            $rows.Add((Convert-AuditFieldsToCheck -Fields $f -Variables $variables -Index $index))
                        }
                    }
                    $cur.Emitted = $true
                }
            }
            $i = $j + 1; continue
        }

        if ($t -eq '<custom_item>') {
            $parsed = Read-AuditCustomItemFields -Lines $lines -Start ($i + 1)
            $fields = $parsed.Fields
            $i = $parsed.EndIndex + 1

            if (-not $fields.ContainsKey('type') -or -not $fields.ContainsKey('description')) { continue }

            # Inside an open condition -> gating/test item; collect it for the enclosing
            # <if> rather than emitting a standalone (unnamed) row.
            if ($cur -and $cur.CollectingCondition) {
                $cur.ConditionItems.Add($fields)
                continue
            }

            if ((Get-AuditField -Fields $fields -Name 'description') -match '^(Windows \d+ is installed|Windows \d+ installation type|Target is enrolled)') {
                continue
            }
            $index++
            $rows.Add((Convert-AuditFieldsToCheck -Fields $fields -Variables $variables -Index $index))
            continue
        }

        $i++
    }

    return @($rows.ToArray())
}

function ConvertTo-RegistryProviderPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^HKLM\\(.+)$') { return "Registry::HKEY_LOCAL_MACHINE\$($Matches[1])" }
    if ($Path -match '^HKCU\\(.+)$') { return "Registry::HKEY_CURRENT_USER\$($Matches[1])" }
    if ($Path -match '^HKU\\(.+)$') { return "Registry::HKEY_USERS\$($Matches[1])" }
    if ($Path -match '^HKEY_LOCAL_MACHINE\\(.+)$') { return "Registry::HKEY_LOCAL_MACHINE\$($Matches[1])" }
    if ($Path -match '^HKEY_CURRENT_USER\\(.+)$') { return "Registry::HKEY_CURRENT_USER\$($Matches[1])" }
    if ($Path -match '^HKEY_USERS\\(.+)$') { return "Registry::HKEY_USERS\$($Matches[1])" }
    return $Path
}

function Expand-RegistryTargetPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^HKU\\\[USER SID\]\\(.+)$') {
        $suffix = $Matches[1]
        $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
        )
        if ($hives.Count -eq 0) {
            throw 'No loaded HKEY_USERS user SID hives were available for HKU\[USER SID] policy checks.'
        }
        return @($hives | ForEach-Object { "HKU\$($_.PSChildName)\$suffix" })
    }
    if ($Path -match '^HKU\\(.+)$' -and $Matches[1] -notmatch '^S-\d-\d+') {
        $suffix = $Matches[1]
        $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
        )
        if ($hives.Count -eq 0) {
            throw 'No loaded HKEY_USERS user SID hives were available for HKU user policy checks.'
        }
        return @($hives | ForEach-Object { "HKU\$($_.PSChildName)\$suffix" })
    }
    return @($Path)
}

function Get-GuidRegistryCandidatePath {
    param($Target)

    $paths = New-Object System.Collections.Generic.List[string]
    $guidRegKey = Get-ObjectPropertyValue -Object $Target -Name 'GuidRegKey'
    if (-not [string]::IsNullOrWhiteSpace([string]$guidRegKey)) {
        $paths.Add([string]$guidRegKey)
    }

    $targetPath = [string]$Target.Path
    if ($targetPath -match '^(.*\\Providers)\\\{GUID\}\\(.+)$') {
        $providersPath = ConvertTo-RegistryProviderPath $Matches[1]
        try {
            foreach ($provider in (Get-ChildItem -LiteralPath $providersPath -ErrorAction Stop)) {
                $paths.Add($targetPath.Replace('{GUID}', $provider.PSChildName))
            }
        } catch {
            if ($paths.Count -eq 0) {
                $paths.Add($targetPath)
            }
        }
    } else {
        $paths.Add($targetPath)
    }

    return @($paths.ToArray() | Select-Object -Unique)
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return '<not found>' }
    if ($Value -is [array]) { return (($Value | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$Value
}

function ConvertTo-Number {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    $lower = $text.ToLowerInvariant()
    switch ($lower) {
        'enabled' { return 1 }
        'enable' { return 1 }
        'yes' { return 1 }
        'on' { return 1 }
        'true' { return 1 }
        'disabled' { return 0 }
        'disable' { return 0 }
        'no' { return 0 }
        'off' { return 0 }
        'false' { return 0 }
    }
    $normalized = $text -replace ',', ''
    if ($normalized -match '^0x[0-9a-fA-F]+$') { return [Convert]::ToInt64($normalized, 16) }
    $number = 0L
    if ([Int64]::TryParse($normalized, [ref]$number)) { return $number }
    if ($normalized -match '(0x[0-9a-fA-F]+|\d+)') {
        $matchText = $Matches[1]
        if ($matchText -match '^0x') { return [Convert]::ToInt64($matchText, 16) }
        return [Convert]::ToInt64($matchText)
    }
    return $null
}

function ConvertTo-BooleanText {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().ToLowerInvariant()
    switch ($text) {
        'enabled' { return 'true' }
        'enable' { return 'true' }
        'yes' { return 'true' }
        'on' { return 'true' }
        'true' { return 'true' }
        '1' { return 'true' }
        'disabled' { return 'false' }
        'disable' { return 'false' }
        'no' { return 'false' }
        'off' { return 'false' }
        'false' { return 'false' }
        '0' { return 'false' }
        default { return $null }
    }
}

function ConvertFrom-EncodedAlternatives {
    param([string]$Encoded)
    $alternatives = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Encoded)) { return @() }

    foreach ($altText in ($Encoded -split ';')) {
        if ([string]::IsNullOrWhiteSpace($altText)) { continue }
        $items = New-Object System.Collections.Generic.List[string]
        $legacyAlternatives = $null
        foreach ($itemText in ($altText -split ',')) {
            if ($itemText -eq '~') {
                $items.Add('')
                continue
            }
            if ([string]::IsNullOrWhiteSpace($itemText)) { continue }
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($itemText))
            # Older exported catalogs encoded an entire OR expression as one item.
            # Read those catalogs safely while new exports use separate alternatives.
            if ($decoded -match '\s+\|\|\s+') {
                $legacyAlternatives = Split-AuditOrExpression $decoded
                break
            } else {
                $items.Add($decoded)
            }
        }
        if ($null -ne $legacyAlternatives) {
            foreach ($alternative in $legacyAlternatives) {
                $alternatives.Add([pscustomobject]@{ Items = [string[]]@($alternative) })
            }
        } else {
            $alternatives.Add([pscustomobject]@{ Items = [string[]]$items.ToArray() })
        }
    }

    return @($alternatives.ToArray())
}

function Test-RangeExpression {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$Expected
    )

    $actualNumber = ConvertTo-Number $Actual
    if ($null -eq $actualNumber) { return $false }

    $range = $Expected.Trim()
    # -match is case-insensitive, so MIN/MAX match in any case. Whitespace
    # around the brackets, bounds, and '..' is tolerated; anything else falls
    # through to $false so unparseable ranges fail safe (never pass).
    if ($range -match '^\[\s*(MIN|\d+)\s*\.\.\s*(MAX|\d+)\s*\]$') {
        $minText = $Matches[1]
        $maxText = $Matches[2]
    } elseif ($range -match '^(MIN|\d+)\s*\.\.\s*(MAX|\d+)\s*$') {
        $minText = $Matches[1]
        $maxText = $Matches[2]
    } else {
        return $false
    }

    if ($minText -ne 'MIN' -and $actualNumber -lt [int64]$minText) { return $false }
    if ($maxText -ne 'MAX' -and $actualNumber -gt [int64]$maxText) { return $false }
    return $true
}

function ConvertTo-ComparableSet {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [array]) {
        return @($Value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    }
    return @(([string]$Value).Trim())
}

function Test-StringAlternatives {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$EncodedAlternatives,
        [switch]$Contains
    )

    $actualSet = @(ConvertTo-ComparableSet $Actual)
    $alternatives = ConvertFrom-EncodedAlternatives $EncodedAlternatives
    foreach ($alternative in $alternatives) {
        $expectedSet = @($alternative.Items | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
        $matched = $true
        foreach ($expected in $expectedSet) {
            if (-not ($actualSet | Where-Object { $_ -ieq $expected })) {
                $matched = $false
                break
            }
        }
        if ($matched -and (-not $Contains) -and $actualSet.Count -ne $expectedSet.Count) {
            $matched = $false
        }
        if ($matched) { return $true }
    }
    return $false
}

function Test-ScalarValue {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$Operator,
        [string]$Expected,
        [string]$ExpectedData = ''
    )

    $actualNumber = ConvertTo-Number $Actual
    $expectedText = if (-not [string]::IsNullOrWhiteSpace($ExpectedData)) { $ExpectedData.Trim() } elseif ($null -eq $Expected) { '' } else { $Expected.Trim() }

    switch ($Operator) {
        'Equals' {
            $actualBool = ConvertTo-BooleanText $Actual
            $expectedBool = ConvertTo-BooleanText $expectedText
            if ($null -ne $actualBool -and $null -ne $expectedBool) {
                return ($actualBool -eq $expectedBool)
            }
            $expectedNumber = ConvertTo-Number $expectedText
            if ($null -ne $actualNumber -and $null -ne $expectedNumber -and $expectedText -match '^(0x[0-9a-fA-F]+|\d+)$') {
                return ($actualNumber -eq $expectedNumber)
            }
            return (([string]$Actual).Trim() -ieq $expectedText)
        }
        'EqualsNumber' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -eq $expectedNumber)
        }
        'Min' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -ge $expectedNumber)
        }
        'Max' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -le $expectedNumber)
        }
        'NonZeroMax' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -ne 0 -and $actualNumber -le $expectedNumber)
        }
        'Range' {
            return Test-RangeExpression -Actual $Actual -Expected $expectedText
        }
        'In' {
            return Test-StringAlternatives -Actual $Actual -EncodedAlternatives $expectedText
        }
        'ContainsAlternatives' {
            return Test-StringAlternatives -Actual $Actual -EncodedAlternatives $expectedText -Contains
        }
        'Regex' {
            if ($null -eq $Actual) { return $false }
            return ((Format-Value $Actual) -match $expectedText)
        }
        'NotRegex' {
            if ($null -eq $Actual) { return $true }
            return -not ((Format-Value $Actual) -match $expectedText)
        }
        'NotEqual' {
            return -not (([string]$Actual).Trim() -ieq $expectedText)
        }
        'NonEmpty' {
            if ($null -eq $Actual) { return $false }
            if ($Actual -is [array]) { return $Actual.Count -gt 0 }
            return -not [string]::IsNullOrWhiteSpace([string]$Actual)
        }
        'Blank' {
            if ($null -eq $Actual) { return $true }
            if ($Actual -is [array]) { return $Actual.Count -eq 0 }
            return [string]::IsNullOrWhiteSpace([string]$Actual)
        }
        'NotExists' {
            return ($null -eq $Actual)
        }
        default {
            $actualBool = ConvertTo-BooleanText $Actual
            $expectedBool = ConvertTo-BooleanText $expectedText
            if ($null -ne $actualBool -and $null -ne $expectedBool) {
                return ($actualBool -eq $expectedBool)
            }
            return (([string]$Actual).Trim() -ieq $expectedText)
        }
    }
}

function Normalize-Principal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $name = $Value.Trim()
    $name = $name -replace '^\*', ''

    if ($name -match '^S-\d-\d+') {
        try {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($name)
            $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $name.ToUpperInvariant()
        }
    }

    $name = $name -replace '^BUILTIN\\', ''
    $name = $name -replace '^NT AUTHORITY\\', ''
    $name = $name -replace '^NT SERVICE\\', ''
    $name = $name -replace '^RESTRICTED SERVICES\\', ''
    return $name.ToUpperInvariant()
}

function Invoke-NativeCommandCapture {
    # Run a native helper (auditpol.exe, secedit.exe) and capture its exit code and
    # combined stdout/stderr WITHOUT letting a non-zero exit turn into a thrown
    # exception. On PowerShell 7.4+ $PSNativeCommandUseErrorActionPreference defaults
    # to $true, which - combined with the script's $ErrorActionPreference='Stop' -
    # would otherwise surface a bare 'Error 0x........ occurred:' against every check
    # that depends on the tool. We shadow both preferences locally so the caller can
    # inspect the result and emit a clear, single diagnostic instead.
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0

    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
        $exitCode = $LASTEXITCODE
    } catch {
        # Command not found / failed to launch (e.g. tool not on PATH). Surface it as a
        # captured failure rather than letting it abort the check with a raw exception.
        $output = @([string]$_.Exception.Message)
        $exitCode = if ($LASTEXITCODE) { $LASTEXITCODE } else { -1 }
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function Get-FirstNonEmptyLine {
    param([string[]]$Lines)
    $line = @($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($line.Count -eq 0) { return '<no output>' }
    return [string]$line[0]
}

function Get-SecurityPolicy {
    if ($null -ne $script:SecurityPolicy) { return $script:SecurityPolicy }

    # [System.IO.Path]::GetTempPath() always returns a value (unlike $env:TEMP, which
    # can be null in some shells / non-Windows hosts).
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("cis-secpol-{0}.inf" -f ([guid]::NewGuid()))
    try {
        $capture = Invoke-NativeCommandCapture -FilePath 'secedit.exe' -Arguments @('/export', '/cfg', $tempFile)
        if (-not (Test-Path -LiteralPath $tempFile)) {
            throw ("Local security policy could not be exported. secedit.exe /export failed (exit code 0x{0:X8}): {1}. Run this script from an elevated PowerShell prompt on the target host." -f $capture.ExitCode, (Get-FirstNonEmptyLine $capture.Output))
        }
        $policy = @{}
        foreach ($line in Get-Content -LiteralPath $tempFile -Encoding Unicode) {
            if ($line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
                $policy[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $script:SecurityPolicy = $policy
        return $script:SecurityPolicy
    } finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-AuditPolicy {
    if ($null -ne $script:AuditPolicy) { return $script:AuditPolicy }

    # auditpol.exe /get /subcategory:* /r returns "Error 0x00000057 occurred:" on some
    # hosts/locales. Fall back to /category:* (which also enumerates every subcategory)
    # before giving up, and surface a clear diagnostic rather than the raw Win32 error.
    $rows = $null
    $diag = ''
    foreach ($scope in @('/subcategory:*', '/category:*')) {
        $capture = Invoke-NativeCommandCapture -FilePath 'auditpol.exe' -Arguments @('/get', $scope, '/r')
        $text = ($capture.Output -join "`n")
        $looksValid = ($capture.ExitCode -eq 0) -and ($text -match 'Subcategory') -and ($text -notmatch 'Error 0x[0-9A-Fa-f]{8} occurred')
        if ($looksValid) {
            $rows = $capture.Output | ConvertFrom-Csv
            break
        }
        $diag = "auditpol.exe /get $scope /r failed (exit code 0x{0:X8}): {1}" -f $capture.ExitCode, (Get-FirstNonEmptyLine $capture.Output)
    }

    if ($null -eq $rows) {
        throw "Advanced Audit Policy could not be read. $diag. Run 'auditpol /get /category:*' from an elevated PowerShell prompt on the target host to see the underlying error."
    }

    $map = @{}
    foreach ($row in $rows) {
        $guid = [string](Get-ObjectPropertyValue -Object $row -Name 'Subcategory GUID')
        if (-not [string]::IsNullOrWhiteSpace($guid)) {
            $map[$guid.Trim('{}').ToLowerInvariant()] = $row
        }
        $subcategory = [string](Get-ObjectPropertyValue -Object $row -Name 'Subcategory')
        if (-not [string]::IsNullOrWhiteSpace($subcategory)) {
            $map[$subcategory.Trim().ToLowerInvariant()] = $row
        }
    }
    $script:AuditPolicy = $map
    return $script:AuditPolicy
}

function ConvertTo-CanonicalPrincipal {
    # Canonicalize one principal to a comparable key. Well-known friendly
    # names map to their SID; well-formed SIDs are kept as-is; anything else
    # is compared literally (lowercased, trimmed, namespace-stripped). An
    # empty Key means the value could not be resolved (unknown friendly name
    # or malformed SID-like text); callers must treat unresolvable entries as
    # Manual, never as a pass. Empty input resolves to an empty key without
    # flagging, so 'No One' checks keep working.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [pscustomobject]@{ Key = ''; Resolved = $true }
    }
    $name = ([string]$Value).Trim().ToLowerInvariant() -replace '^\*', ''
    $name = $name -replace '^(builtin|nt authority|nt service|restricted services|nt virtual machine)\s*\\', ''
    $name = $name.Trim()
    if ($name -match '^s-\d+(-\d+)+$') {
        return [pscustomobject]@{ Key = $name; Resolved = $true }
    }
    if ($name -like 's-*') {
        return [pscustomobject]@{ Key = ''; Resolved = $false }
    }
    switch ($name) {
        'administrators' { return [pscustomobject]@{ Key = 's-1-5-32-544'; Resolved = $true } }
        'users' { return [pscustomobject]@{ Key = 's-1-5-32-545'; Resolved = $true } }
        'guests' { return [pscustomobject]@{ Key = 's-1-5-32-546'; Resolved = $true } }
        'power users' { return [pscustomobject]@{ Key = 's-1-5-32-547'; Resolved = $true } }
        'backup operators' { return [pscustomobject]@{ Key = 's-1-5-32-551'; Resolved = $true } }
        'replicator' { return [pscustomobject]@{ Key = 's-1-5-32-552'; Resolved = $true } }
        'remote desktop users' { return [pscustomobject]@{ Key = 's-1-5-32-555'; Resolved = $true } }
        'remote management users' { return [pscustomobject]@{ Key = 's-1-5-32-580'; Resolved = $true } }
        'everyone' { return [pscustomobject]@{ Key = 's-1-1-0'; Resolved = $true } }
        'system' { return [pscustomobject]@{ Key = 's-1-5-18'; Resolved = $true } }
        'local system' { return [pscustomobject]@{ Key = 's-1-5-18'; Resolved = $true } }
        'local service' { return [pscustomobject]@{ Key = 's-1-5-19'; Resolved = $true } }
        'network service' { return [pscustomobject]@{ Key = 's-1-5-20'; Resolved = $true } }
        'service' { return [pscustomobject]@{ Key = 's-1-5-6'; Resolved = $true } }
        'authenticated users' { return [pscustomobject]@{ Key = 's-1-5-11'; Resolved = $true } }
        'interactive' { return [pscustomobject]@{ Key = 's-1-5-4'; Resolved = $true } }
        'virtual machines' { return [pscustomobject]@{ Key = 's-1-5-83-0'; Resolved = $true } }
        default { return [pscustomobject]@{ Key = $name; Resolved = $false } }
    }
}

function Test-PrincipalAlternatives {
    param(
        [string]$ActualRaw,
        [string]$EncodedAlternatives,
        [string]$Operator
    )

    $actual = @()
    $sawUnresolved = $false
    if (-not [string]::IsNullOrWhiteSpace($ActualRaw)) {
        foreach ($entry in ($ActualRaw -split ',')) {
            $canon = ConvertTo-CanonicalPrincipal $entry
            if ($canon.Key -ne '') { $actual += $canon.Key }
            if (-not $canon.Resolved) { $sawUnresolved = $true }
        }
    }

    $alternatives = ConvertFrom-EncodedAlternatives $EncodedAlternatives
    foreach ($alternative in $alternatives) {
        $expected = @()
        $alternativeUnresolved = $false
        foreach ($item in $alternative.Items) {
            $canon = ConvertTo-CanonicalPrincipal $item
            if ($canon.Key -ne '') { $expected += $canon.Key }
            if (-not $canon.Resolved) { $alternativeUnresolved = $true }
        }
        $matched = $true
        foreach ($item in $expected) {
            if ($actual -notcontains $item) {
                $matched = $false
                break
            }
        }
        if ($matched -and $Operator -eq 'ExactAlternatives' -and $actual.Count -ne $expected.Count) {
            $matched = $false
        }
        if ($matched) {
            return $true
        }
        if ($alternativeUnresolved) {
            $sawUnresolved = $true
        }
    }
    # A decisive match passes; a decisive mismatch fails. Anything that could
    # not be resolved stays Manual ($null) instead of failing open or closed
    # on a naming guess.
    if ($sawUnresolved) {
        return $null
    }
    return $false
}

function Test-RegistryTargetValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        $Target
    )

    $providerPath = ConvertTo-RegistryProviderPath $Path
    $actual = $null
    $found = $true
    try {
        $actual = Get-ItemPropertyValue -LiteralPath $providerPath -Name $Target.Name -ErrorAction Stop
    } catch {
        $found = $false
        $actual = $null
    }

    $actualPart = "{0}:{1}={2}" -f $Path, $Target.Name, (Format-Value $actual)
    $regOption = [string](Get-ObjectPropertyValue -Object $Target -Name 'RegOption')
    $operator = [string](Get-ObjectPropertyValue -Object $Target -Name 'Operator')

    if ($regOption -eq 'MUST_NOT_EXIST' -or $operator -eq 'NotExists') {
        return [pscustomobject]@{ Actual = $actualPart; Pass = (-not $found) }
    }

    # Only CAN_BE_NULL may pass on a missing value. Any other collection
    # failure or missing key is unknown, not a failure: surface Manual
    # (Pass = $null) rather than guessing Fail.
    if (-not $found) {
        if ($regOption -eq 'CAN_BE_NULL') {
            return [pscustomobject]@{ Actual = $actualPart; Pass = $true }
        }
        return [pscustomobject]@{ Actual = $actualPart; Pass = $null }
    }

    $expected = [string](Get-ObjectPropertyValue -Object $Target -Name 'Expected')
    $expectedDataValue = Get-ObjectPropertyValue -Object $Target -Name 'ExpectedData'
    $expectedData = if ($null -ne $expectedDataValue) { [string]$expectedDataValue } else { '' }
    $pass = Test-ScalarValue -Actual $actual -Operator $operator -Expected $expected -ExpectedData $expectedData
    return [pscustomobject]@{ Actual = $actualPart; Pass = $pass }
}

function Test-RegistryCheck {
    param($Check)
    $targets = $Check.TargetsJson | ConvertFrom-Json
    $actualParts = New-Object System.Collections.Generic.List[string]
    $allPass = $true
    $sawManual = $false

    foreach ($target in @($targets)) {
        $guidRegKey = Get-ObjectPropertyValue -Object $target -Name 'GuidRegKey'
        $isGuidRegistry = (([string]$target.Path) -match '\\\{GUID\}\\') -or (-not [string]::IsNullOrWhiteSpace([string]$guidRegKey))

        if ($isGuidRegistry) {
            $candidateResults = New-Object System.Collections.Generic.List[object]
            foreach ($candidatePath in (Get-GuidRegistryCandidatePath $target)) {
                foreach ($expandedPath in (Expand-RegistryTargetPath $candidatePath)) {
                    $result = Test-RegistryTargetValue -Path $expandedPath -Target $target
                    $candidateResults.Add($result)
                    $actualParts.Add($result.Actual)
                }
            }
            if ($candidateResults.Count -eq 0 -or -not ($candidateResults | Where-Object { $_.Pass })) {
                if ($candidateResults | Where-Object { $null -eq $_.Pass }) {
                    $sawManual = $true
                } else {
                    $allPass = $false
                }
            }
            continue
        }

        foreach ($expandedPath in (Expand-RegistryTargetPath $target.Path)) {
            $result = Test-RegistryTargetValue -Path $expandedPath -Target $target
            $actualParts.Add($result.Actual)
            if ($null -eq $result.Pass) {
                $sawManual = $true
            } elseif (-not $result.Pass) {
                $allPass = $false
            }
        }
    }

    $overall = if (-not $allPass) { $false } elseif ($sawManual) { $null } else { $true }
    return [pscustomobject]@{
        Actual = ($actualParts -join ' | ')
        Pass = $overall
    }
}

function Test-AccountPolicyCheck {
    param($Check)
    $policy = Get-SecurityPolicy
    $actual = if ($policy.ContainsKey($Check.Target)) { $policy[$Check.Target] } else { $null }
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = (Format-Value $actual); Pass = $pass }
}

function Test-UserRightCheck {
    param($Check)
    $policy = Get-SecurityPolicy
    $actual = if ($policy.ContainsKey($Check.Target)) { $policy[$Check.Target] } else { '' }
    $pass = Test-PrincipalAlternatives -ActualRaw $actual -EncodedAlternatives $Check.ExpectedData -Operator $Check.Operator
    $display = if ([string]::IsNullOrWhiteSpace($actual)) { 'No One' } else { (($actual -split ',' | ForEach-Object { Normalize-Principal $_ }) -join '; ') }
    return [pscustomobject]@{ Actual = $display; Pass = $pass }
}

function ConvertTo-AuditSettingTokens {
    # Split an inclusion setting such as 'Success and Failure', 'Success,
    # Failure', or 'Success,Failure' into canonical tokens. Matching is
    # case-insensitive and ignores surrounding whitespace. Unknown tokens are
    # kept literal so they mismatch downstream (Fail, which is safe) instead
    # of being silently dropped (which could pass incorrectly).
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    $tokens = @()
    foreach ($part in ([string]$Value -split '\s*,\s*|\s+and\s+')) {
        $clean = $part.Trim()
        if ($clean -eq '') { continue }
        if ($clean -ieq 'success') { $tokens += 'Success' }
        elseif ($clean -ieq 'failure') { $tokens += 'Failure' }
        else { $tokens += $clean }
    }
    return @($tokens | Select-Object -Unique)
}

function Test-AuditPolicyCheck {
    param($Check)
    $audit = Get-AuditPolicy
    $key = $Check.Target.Trim('{}').ToLowerInvariant()
    if (-not $audit.ContainsKey($key)) {
        return [pscustomobject]@{ Actual = '<not found>'; Pass = $false }
    }
    $actual = $audit[$key].'Inclusion Setting'
    $actualTokens = @(ConvertTo-AuditSettingTokens $actual)
    $alternatives = ConvertFrom-EncodedAlternatives $Check.ExpectedData
    $pass = $false
    foreach ($alternative in $alternatives) {
        $expectedTokens = @()
        foreach ($item in $alternative.Items) {
            $expectedTokens += ConvertTo-AuditSettingTokens $item
        }
        $expectedTokens = @($expectedTokens | Select-Object -Unique)
        $matched = $true
        foreach ($token in $expectedTokens) {
            if ($actualTokens -notcontains $token) {
                $matched = $false
                break
            }
        }
        if ($matched -and $actualTokens.Count -eq $expectedTokens.Count) {
            $pass = $true
            break
        }
    }
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Test-ServiceCheck {
    param($Check)
    $name = $Check.Target
    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($name -replace "'", "''")) -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $pass = $Check.Operator -in @('DisabledOrNotInstalled', 'NotInstalled')
        return [pscustomobject]@{ Actual = 'Not Installed'; Pass = $pass }
    }
    $actual = $service.StartMode
    $pass = if ($Check.Operator -eq 'DisabledOrNotInstalled') { $actual -eq 'Disabled' } else { $actual -eq $Check.Expected }
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Test-FirewallCheck {
    param($Check)
    $parts = $Check.Target -split ':', 2
    $profileName = $parts[0]
    $propertyName = $parts[1]
    $profile = Get-NetFirewallProfile -Profile $profileName -ErrorAction Stop
    $actual = $profile.$propertyName
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected
    return [pscustomobject]@{ Actual = (Format-Value $actual); Pass = $pass }
}

function Test-LocalAccountCheck {
    param($Check)
    $suffix = if ($Check.Target -eq 'ADMINISTRATOR_ACCOUNT') { '-500' } else { '-501' }
    $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' |
        Where-Object { $_.SID.EndsWith($suffix) } |
        Select-Object -First 1

    if ($null -eq $account) {
        return [pscustomobject]@{ Actual = '<not found>'; Pass = $false }
    }

    if ($Check.Operator -eq 'Disabled') {
        return [pscustomobject]@{ Actual = ("{0}; Disabled={1}" -f $account.Name, $account.Disabled); Pass = [bool]$account.Disabled }
    }

    $pass = Test-ScalarValue -Actual $account.Name -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = $account.Name; Pass = $pass }
}

function Test-PowerShellCheck {
    param($Check)

    if (-not $script:AllowEmbeddedScripts) {
        return [pscustomobject]@{
            Actual = 'Embedded PowerShell was not executed. Re-run with -AllowEmbeddedScripts if this audit file is trusted.'
            Pass = $null
        }
    }

    $scriptBlock = [scriptblock]::Create($Check.Target)
    $output = & $scriptBlock 6>&1 5>&1 4>&1 3>&1 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.InformationRecord]) {
            [string]$_.MessageData
        } else {
            [string]$_
        }
    }
    $actual = (($output | Where-Object { $null -ne $_ }) -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($actual)) {
        $actual = '<no output>'
    }
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Test-ChecklistExcluded {
    # Catalog-only opt-out (Windows checks catalogs): a 'Checklist' column
    # value of exactly '0' excludes the row from evaluation. Uses ordinal
    # string comparison so values like '00' or '0.0' still evaluate normally.
    # Missing/empty/any other value evaluates normally. Audit-file rows never
    # carry Checklist, so the .audit path is unaffected.
    param($Check)
    $value = [string](Get-ObjectPropertyValue -Object $Check -Name 'Checklist')
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }
    return [string]::Equals($value.Trim(), '0', [System.StringComparison]::Ordinal)
}

function Invoke-NessusCheck {
    param($Check)
    switch ($Check.Method) {
        'Registry' { return Test-RegistryCheck $Check }
        'AccountPolicy' { return Test-AccountPolicyCheck $Check }
        'UserRight' { return Test-UserRightCheck $Check }
        'AuditPolicy' { return Test-AuditPolicyCheck $Check }
        'Service' { return Test-ServiceCheck $Check }
        'Firewall' { return Test-FirewallCheck $Check }
        'LocalAccount' { return Test-LocalAccountCheck $Check }
        'PowerShell' { return Test-PowerShellCheck $Check }
        default {
            $manualReason = [string](Get-ObjectPropertyValue -Object $Check -Name 'ManualReason')
            return [pscustomobject]@{
                Actual = if ([string]::IsNullOrWhiteSpace($manualReason)) { 'Manual review required' } else { $manualReason }
                Pass = $null
            }
        }
    }
}

function ConvertTo-HtmlEscaped {
    param($Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    try {
        return [System.Net.WebUtility]::HtmlEncode($text)
    } catch {
        $safe = $text -replace '&', '&amp;'
        $safe = $safe -replace '<', '&lt;'
        $safe = $safe -replace '>', '&gt;'
        $safe = $safe -replace '"', '&quot;'
        return $safe
    }
}

function Get-AuditReportArea {
    param([string]$CheckName)
    if ([string]::IsNullOrWhiteSpace($CheckName)) { return 'Other' }
    $trimmed = $CheckName.Trim()
    $match = [regex]::Match($trimmed, '^(\d+)')
    if ($match.Success) { return ('Section ' + $match.Groups[1].Value) }
    return 'Other'
}

function ConvertTo-LogoDataUri {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        return ''
    }
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
    if ($bytes.Length -gt 524288) { return '' }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $mime = ''
    if ($ext -eq '.png') { $mime = 'image/png' }
    elseif ($ext -eq '.jpg' -or $ext -eq '.jpeg') { $mime = 'image/jpeg' }
    elseif ($ext -eq '.gif') { $mime = 'image/gif' }
    elseif ($ext -eq '.svg') { $mime = 'image/svg+xml' }
    else { return '' }
    return ('data:' + $mime + ';base64,' + [Convert]::ToBase64String($bytes))
}

function Export-AuditHtmlReport {
    param(
        [array]$Results,
        [Parameter(Mandatory)][string]$Path,
        [string]$Title = '',
        [string]$Company = '',
        [string]$Client = '',
        [string]$Assessor = '',
        [string]$InputLabel = '',
        [string]$LogoFile = ''
    )

    $rows = @()
    if ($null -ne $Results) { $rows = @($Results) }
    $passCount = 0
    $failCount = 0
    $manualCount = 0
    foreach ($row in $rows) {
        $status = ''
        if ($null -ne $row) {
            $prop = $row.PSObject.Properties['Pass/Fail/Manual']
            if ($null -ne $prop) { $status = [string]$prop.Value }
        }
        $clean = $status.Trim()
        if ([string]::Equals($clean, 'Pass', [System.StringComparison]::OrdinalIgnoreCase)) { $passCount++ }
        elseif ([string]::Equals($clean, 'Fail', [System.StringComparison]::OrdinalIgnoreCase)) { $failCount++ }
        else { $manualCount++ }
    }
    $totalCount = $rows.Count
    $passRate = 0
    if ($totalCount -gt 0) { $passRate = [math]::Round(($passCount * 100.0) / $totalCount) }

    $reportTitle = $Title.Trim()
    if ([string]::IsNullOrWhiteSpace($reportTitle)) { $reportTitle = 'Audit Results Report' }
    $runDate = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    $hostName = ''
    try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = '' }
    if ([string]::IsNullOrWhiteSpace($hostName) -and $null -ne $env:COMPUTERNAME) { $hostName = [string]$env:COMPUTERNAME }
    if ([string]::IsNullOrWhiteSpace($hostName) -and $null -ne $env:HOSTNAME) { $hostName = [string]$env:HOSTNAME }
    if ([string]::IsNullOrWhiteSpace($hostName)) { $hostName = 'Local host' }

    $areas = @{}
    foreach ($row in $rows) {
        $name = ''
        if ($null -ne $row) {
            $p = $row.PSObject.Properties['CHECK']
            if ($null -ne $p) { $name = [string]$p.Value }
        }
        $area = Get-AuditReportArea $name
        if (-not $areas.ContainsKey($area)) { $areas[$area] = 0 }
        $areas[$area] = [int]$areas[$area] + 1
    }
    $sortedAreas = @($areas.Keys | Sort-Object)
    $maxArea = 1
    foreach ($key in $sortedAreas) { if ([int]$areas[$key] -gt $maxArea) { $maxArea = [int]$areas[$key] } }

    $radius = 54
    $circ = 2 * [math]::PI * $radius
    $passLen = 0
    $failLen = 0
    $manualLen = 0
    if ($totalCount -gt 0) {
        $passLen = [math]::Round(($passCount / [double]$totalCount) * $circ, 2)
        $failLen = [math]::Round(($failCount / [double]$totalCount) * $circ, 2)
        $manualLen = [math]::Round(($manualCount / [double]$totalCount) * $circ, 2)
    }
    $failOffset = (0 - $passLen)
    $manualOffset = (0 - $passLen - $failLen)

    $logoUri = ConvertTo-LogoDataUri $LogoFile
    $hasLogo = -not [string]::IsNullOrWhiteSpace($logoUri)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>' + (ConvertTo-HtmlEscaped $reportTitle) + '</title>'))
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(':root{--ink:#1f2937;--muted:#6b7280;--line:#e5e7eb;--bg:#f8fafc;--card:#ffffff;--pass:#16803d;--pass-bg:#e7f4ec;--fail:#b3261e;--fail-bg:#fdecea;--manual:#8a6d00;--manual-bg:#fef6d8;--accent:#1d4ed8;}')
    [void]$sb.AppendLine('*{box-sizing:border-box;}body{margin:0;font-family:Georgia,"Times New Roman",Verdana,system-ui,sans-serif;color:var(--ink);background:var(--bg);line-height:1.55;}')
    [void]$sb.AppendLine('.wrap{max-width:1024px;margin:0 auto;padding:24px 20px 64px;}header.report{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;}')
    [void]$sb.AppendLine('.brand-row{display:flex;gap:16px;align-items:center;}.logo{height:52px;width:auto;max-width:220px;object-fit:contain;border:1px solid var(--line);border-radius:8px;background:#fff;}')
    [void]$sb.AppendLine('h1{font-size:28px;margin:6px 0;}h2{font-size:20px;margin:32px 0 12px;}h3{font-size:16px;margin:20px 0 8px;}')
    [void]$sb.AppendLine('.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 20px;margin-top:14px;font-size:14px;}')
    [void]$sb.AppendLine('.meta dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;}.meta dd{margin:0;font-weight:600;}')
    [void]$sb.AppendLine('.grid{display:grid;grid-template-columns:300px 1fr;gap:20px;margin-top:20px;}@media(max-width:760px){.grid{grid-template-columns:1fr;}}')
    [void]$sb.AppendLine('.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;}')
    [void]$sb.AppendLine('.stat-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;}.stat{flex:1;min-width:110px;border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center;}.stat b{display:block;font-size:24px;}')
    [void]$sb.AppendLine('.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.03em;}')
    [void]$sb.AppendLine('.badge.pass{background:var(--pass-bg);color:var(--pass);border:1px solid var(--pass);}.badge.fail{background:var(--fail-bg);color:var(--fail);border:1px solid var(--fail);}.badge.manual{background:var(--manual-bg);color:var(--manual);border:1px solid var(--manual);}')
    [void]$sb.AppendLine('.toolbar{position:sticky;top:0;background:var(--bg);padding:12px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center;z-index:5;}')
    [void]$sb.AppendLine('.toolbar button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:6px 14px;cursor:pointer;font-size:14px;}')
    [void]$sb.AppendLine('.toolbar button.active{background:var(--ink);color:#fff;border-color:var(--ink);}')
    [void]$sb.AppendLine('.toolbar input{flex:1;min-width:180px;border:1px solid var(--line);border-radius:999px;padding:7px 14px;font-size:14px;}')
    [void]$sb.AppendLine('.toc{columns:2;column-gap:24px;font-size:14px;}@media(max-width:760px){.toc{columns:1;}}.toc a{color:var(--accent);text-decoration:none;}.toc li{margin:3px 0;break-inside:avoid;}')
    [void]$sb.AppendLine('.finding{border:1px solid var(--line);border-left-width:6px;border-radius:10px;background:#fff;padding:14px 16px;margin:12px 0;}')
    [void]$sb.AppendLine('.finding.pass{border-left-color:var(--pass);}.finding.fail{border-left-color:var(--fail);}.finding.manual{border-left-color:var(--manual);}')
    [void]$sb.AppendLine('.finding h3{margin:0 0 6px;font-size:15px;}.kv{font-size:14px;margin:4px 0;}.kv span{color:var(--muted);}.backtop{font-size:13px;}')
    [void]$sb.AppendLine('table.details{width:100%;border-collapse:collapse;font-size:14px;background:#fff;}table.details th,table.details td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top;}table.details th{background:#f1f5f9;}')
    [void]$sb.AppendLine('.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;}footer{margin-top:32px;font-size:13px;color:var(--muted);}')
    [void]$sb.AppendLine('@media print{.toolbar{display:none;}.wrap{max-width:none;padding:0;}header.report,.card,.finding{break-inside:avoid;}body{background:#fff;}a{color:#000;}}')
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body id="top">')
    [void]$sb.AppendLine('<div class="wrap">')
    [void]$sb.AppendLine('<header class="report">')
    [void]$sb.AppendLine('<div class="brand-row">')
    if ($hasLogo) {
        [void]$sb.AppendLine(('<img class="logo" alt="Company logo" src="' + $logoUri + '">'))
    }
    [void]$sb.AppendLine('<div>')
    [void]$sb.AppendLine(('<div style="color:var(--muted);font-size:13px;">' + (ConvertTo-HtmlEscaped $Company) + '</div>'))
    [void]$sb.AppendLine(('<h1>' + (ConvertTo-HtmlEscaped $reportTitle) + '</h1>'))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<dl class="meta">')
    [void]$sb.AppendLine(('<div><dt>Client</dt><dd>' + (ConvertTo-HtmlEscaped $Client) + '</dd></div>'))
    [void]$sb.AppendLine(('<div><dt>Assessor</dt><dd>' + (ConvertTo-HtmlEscaped $Assessor) + '</dd></div>'))
    [void]$sb.AppendLine(('<div><dt>Date</dt><dd>' + (ConvertTo-HtmlEscaped $runDate) + '</dd></div>'))
    [void]$sb.AppendLine(('<div><dt>Host</dt><dd>' + (ConvertTo-HtmlEscaped $hostName) + '</dd></div>'))
    [void]$sb.AppendLine(('<div><dt>Input file</dt><dd>' + (ConvertTo-HtmlEscaped $InputLabel) + '</dd></div>'))
    [void]$sb.AppendLine('<div><dt>Tool</dt><dd>AuditRunner local runner (partial Nessus-format support)</dd></div>')
    [void]$sb.AppendLine('</dl>')
    [void]$sb.AppendLine('</header>')

    [void]$sb.AppendLine('<div class="grid">')
    [void]$sb.AppendLine('<section class="card">')
    [void]$sb.AppendLine('<h2 style="margin-top:0;">Executive summary</h2>')
    [void]$sb.AppendLine(('<p><strong>' + $passCount + ' of ' + $totalCount + ' checks passed (' + $passRate + '% pass rate).</strong></p>'))
    [void]$sb.AppendLine(('<svg role="img" aria-label="Results: ' + $passCount + ' pass, ' + $failCount + ' fail, ' + $manualCount + ' manual" viewBox="0 0 140 140" width="220" height="220">'))
    [void]$sb.AppendLine('<circle cx="70" cy="70" r="54" fill="none" stroke="#e5e7eb" stroke-width="18"/>')
    if ($totalCount -gt 0) {
        if ($passLen -gt 0) {
            [void]$sb.AppendLine(('<circle cx="70" cy="70" r="54" fill="none" stroke="#16803d" stroke-width="18" stroke-dasharray="' + $passLen + ' ' + ($circ - $passLen) + '" stroke-dashoffset="0" transform="rotate(-90 70 70)"/>'))
        }
        if ($failLen -gt 0) {
            [void]$sb.AppendLine(('<circle cx="70" cy="70" r="54" fill="none" stroke="#b3261e" stroke-width="18" stroke-dasharray="' + $failLen + ' ' + ($circ - $failLen) + '" stroke-dashoffset="' + $failOffset + '" transform="rotate(-90 70 70)"/>'))
        }
        if ($manualLen -gt 0) {
            [void]$sb.AppendLine(('<circle cx="70" cy="70" r="54" fill="none" stroke="#d9a400" stroke-width="18" stroke-dasharray="' + $manualLen + ' ' + ($circ - $manualLen) + '" stroke-dashoffset="' + $manualOffset + '" transform="rotate(-90 70 70)"/>'))
        }
    }
    [void]$sb.AppendLine(('<text x="70" y="66" text-anchor="middle" font-size="22" font-weight="bold">' + $passRate + '%</text>'))
    [void]$sb.AppendLine(('<text x="70" y="86" text-anchor="middle" font-size="11" fill="#6b7280">' + $passCount + ' / ' + $totalCount + ' passed</text>'))
    [void]$sb.AppendLine('</svg>')
    [void]$sb.AppendLine('<div class="stat-row">')
    [void]$sb.AppendLine(('<div class="stat"><b style="color:var(--pass);">' + $passCount + '</b>Pass</div>'))
    [void]$sb.AppendLine(('<div class="stat"><b style="color:var(--fail);">' + $failCount + '</b>Fail</div>'))
    [void]$sb.AppendLine(('<div class="stat"><b style="color:var(--manual);">' + $manualCount + '</b>Manual</div>'))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<section class="card">')
    [void]$sb.AppendLine('<h2 style="margin-top:0;">Results by area</h2>')
    [void]$sb.AppendLine('<p style="color:var(--muted);font-size:14px;">Grouped by the leading number of each check name.</p>')
    if ($sortedAreas.Count -eq 0) {
        [void]$sb.AppendLine('<p>No checks were evaluated.</p>')
    } else {
        $barHeight = 22
        $gap = 10
        $svgHeight = ($sortedAreas.Count * ($barHeight + $gap)) + 10
        $barMax = 480
        [void]$sb.AppendLine(('<svg role="img" aria-label="Checks per area" viewBox="0 0 640 ' + $svgHeight + '" width="100%">'))
        $y = 5
        foreach ($key in $sortedAreas) {
            $count = [int]$areas[$key]
            $width = [math]::Round(($count / [double]$maxArea) * $barMax)
            if ($width -lt 4) { $width = 4 }
            [void]$sb.AppendLine(('<text x="0" y="' + ($y + 15) + '" font-size="12">' + (ConvertTo-HtmlEscaped $key) + ' (' + $count + ')</text>'))
            [void]$sb.AppendLine(('<rect x="140" y="' + $y + '" width="' + $width + '" height="' + $barHeight + '" rx="6" fill="#1d4ed8"><title>' + (ConvertTo-HtmlEscaped $key) + ': ' + $count + ' checks</title></rect>'))
            $y = $y + $barHeight + $gap
        }
        [void]$sb.AppendLine('</svg>')
    }
    [void]$sb.AppendLine('</section>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<section class="card" style="margin-top:20px;">')
    [void]$sb.AppendLine('<h2 style="margin-top:0;">Contents</h2>')
    [void]$sb.AppendLine('<ol class="toc">')
    $n = 0
    foreach ($row in $rows) {
        $n++
        $name = ''
        $status = 'Manual'
        if ($null -ne $row) {
            $p1 = $row.PSObject.Properties['CHECK']
            if ($null -ne $p1) { $name = [string]$p1.Value }
            $p2 = $row.PSObject.Properties['Pass/Fail/Manual']
            if ($null -ne $p2) { $status = ([string]$p2.Value).Trim() }
        }
        if ([string]::Equals($status, 'Pass', [System.StringComparison]::OrdinalIgnoreCase)) { $cls = 'pass' }
        elseif ([string]::Equals($status, 'Fail', [System.StringComparison]::OrdinalIgnoreCase)) { $cls = 'fail' }
        else { $cls = 'manual'; $status = 'Manual' }
        [void]$sb.AppendLine(('<li><span class="badge ' + $cls + '">' + (ConvertTo-HtmlEscaped $status) + '</span> <a href="#finding-' + $n + '">' + (ConvertTo-HtmlEscaped $name) + '</a></li>'))
    }
    [void]$sb.AppendLine('</ol>')
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<div class="toolbar" role="search">')
    [void]$sb.AppendLine('<button type="button" data-filter="All" class="active">All</button>')
    [void]$sb.AppendLine('<button type="button" data-filter="Pass">Pass</button>')
    [void]$sb.AppendLine('<button type="button" data-filter="Fail">Fail</button>')
    [void]$sb.AppendLine('<button type="button" data-filter="Manual">Manual</button>')
    [void]$sb.AppendLine('<input id="finding-search" type="search" placeholder="Search checks, actual or expected values...">')
    [void]$sb.AppendLine('</div>')

    foreach ($group in @('Fail', 'Manual', 'Pass')) {
        if ($group -eq 'Fail') { $groupLower = 'fail' }
        elseif ($group -eq 'Manual') { $groupLower = 'manual' }
        else { $groupLower = 'pass' }
        [void]$sb.AppendLine(('<h2>' + $group + ' findings</h2>'))
        $n = 0
        $groupEmpty = $true
        foreach ($row in $rows) {
            $n++
            $name = ''
            $actual = ''
            $expected = ''
            $status = 'Manual'
            if ($null -ne $row) {
                $p1 = $row.PSObject.Properties['CHECK']
                if ($null -ne $p1) { $name = [string]$p1.Value }
                $p2 = $row.PSObject.Properties['Actual Value']
                if ($null -ne $p2) { $actual = [string]$p2.Value }
                $p3 = $row.PSObject.Properties['Expected Value']
                if ($null -ne $p3) { $expected = [string]$p3.Value }
                $p4 = $row.PSObject.Properties['Pass/Fail/Manual']
                if ($null -ne $p4) { $status = ([string]$p4.Value).Trim() }
            }
            $norm = $status
            if (-not ([string]::Equals($norm, 'Pass', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($norm, 'Fail', [System.StringComparison]::OrdinalIgnoreCase))) { $norm = 'Manual' }
            if (-not [string]::Equals($norm, $group, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $groupEmpty = $false
            [void]$sb.AppendLine(('<article class="finding ' + $groupLower + '" id="finding-' + $n + '" data-status="' + $group + '">'))
            [void]$sb.AppendLine(('<h3>' + (ConvertTo-HtmlEscaped $name) + '</h3>'))
            [void]$sb.AppendLine(('<p><span class="badge ' + $groupLower + '">' + (ConvertTo-HtmlEscaped $norm) + '</span></p>'))
            [void]$sb.AppendLine(('<p class="kv"><span>Actual:</span> ' + (ConvertTo-HtmlEscaped $actual) + '</p>'))
            [void]$sb.AppendLine(('<p class="kv"><span>Expected:</span> ' + (ConvertTo-HtmlEscaped $expected) + '</p>'))
            [void]$sb.AppendLine('<p class="backtop"><a href="#top">Back to top</a></p>')
            [void]$sb.AppendLine('</article>')
        }
        if ($groupEmpty) {
            [void]$sb.AppendLine(('<p class="finding ' + $groupLower + '" data-status="' + $group + '">No ' + $group.ToLowerInvariant() + ' findings.</p>'))
        }
    }

    [void]$sb.AppendLine('<h2>Details table</h2>')
    [void]$sb.AppendLine('<div class="table-wrap">')
    [void]$sb.AppendLine('<table class="details" id="details-table">')
    [void]$sb.AppendLine('<thead><tr><th>Check</th><th>Status</th><th>Actual</th><th>Expected</th></tr></thead>')
    [void]$sb.AppendLine('<tbody>')
    foreach ($row in $rows) {
        $name = ''
        $actual = ''
        $expected = ''
        $status = 'Manual'
        if ($null -ne $row) {
            $p1 = $row.PSObject.Properties['CHECK']
            if ($null -ne $p1) { $name = [string]$p1.Value }
            $p2 = $row.PSObject.Properties['Actual Value']
            if ($null -ne $p2) { $actual = [string]$p2.Value }
            $p3 = $row.PSObject.Properties['Expected Value']
            if ($null -ne $p3) { $expected = [string]$p3.Value }
            $p4 = $row.PSObject.Properties['Pass/Fail/Manual']
            if ($null -ne $p4) { $status = ([string]$p4.Value).Trim() }
        }
        $norm = $status
        if (-not ([string]::Equals($norm, 'Pass', [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($norm, 'Fail', [System.StringComparison]::OrdinalIgnoreCase))) { $norm = 'Manual' }
        if ([string]::Equals($norm, 'Pass', [System.StringComparison]::OrdinalIgnoreCase)) { $cls = 'pass' }
        elseif ([string]::Equals($norm, 'Fail', [System.StringComparison]::OrdinalIgnoreCase)) { $cls = 'fail' }
        else { $cls = 'manual' }
        [void]$sb.AppendLine(('<tr data-status="' + $norm + '"><td>' + (ConvertTo-HtmlEscaped $name) + '</td><td><span class="badge ' + $cls + '">' + (ConvertTo-HtmlEscaped $norm) + '</span></td><td>' + (ConvertTo-HtmlEscaped $actual) + '</td><td>' + (ConvertTo-HtmlEscaped $expected) + '</td></tr>'))
    }
    [void]$sb.AppendLine('</tbody>')
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine('<p>Method note: this report was produced by a local runner with partial Nessus-format support. Unsupported or blocked checks are kept as Manual and need separate review. A finished run only means results were exported; completion is not a compliance verdict. Review each Fail and Manual row before signing off.</p>')
    [void]$sb.AppendLine('</footer>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('(function(){var current="All";var box=document.getElementById("finding-search");function matches(el){var st=el.getAttribute("data-status")||"";if(current!=="All"&&st!==current){return false;}var q=(box&&box.value||"").toLowerCase();if(!q){return true;}var text=(el.textContent||"").toLowerCase();return text.indexOf(q)>-1;}function apply(){var cards=document.querySelectorAll(".finding");for(var i=0;i<cards.length;i++){cards[i].style.display=matches(cards[i])?"":"none";}var rows=document.querySelectorAll("#details-table tbody tr");for(var j=0;j<rows.length;j++){rows[j].style.display=matches(rows[j])?"":"none";}}var buttons=document.querySelectorAll(".toolbar button");for(var k=0;k<buttons.length;k++){buttons[k].addEventListener("click",function(){current=this.getAttribute("data-filter");for(var m=0;m<buttons.length;m++){buttons[m].className=(buttons[m]===this)?"active":"";}apply();});}if(box){box.addEventListener("input",apply);}})();')
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        [void](New-Item -ItemType Directory -Force -Path $parent)
    }
    $html = $sb.ToString()
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding $false))
}

if ([string]::IsNullOrWhiteSpace($AuditPath) -and [string]::IsNullOrWhiteSpace($ChecksPath)) {
    throw 'Specify either -AuditPath for a Nessus .audit file or -ChecksPath for a checks catalog CSV.'
}

# Preflight (read-only, no network): warn once per missing host tool so the
# operator knows which checks will fall back to Manual. Informational only:
# exit code and per-check try/catch semantics are unchanged.
$preflightTools = @(
    [pscustomobject]@{ Name = 'secedit.exe'; Area = 'account-policy and user-right checks' }
    [pscustomobject]@{ Name = 'auditpol.exe'; Area = 'advanced audit-policy checks' }
)
foreach ($preflightTool in $preflightTools) {
    if (-not (Get-Command $preflightTool.Name -ErrorAction SilentlyContinue)) {
        Write-Warning ("{0} was not found on PATH; {1} will report Manual." -f $preflightTool.Name, $preflightTool.Area)
    }
}

if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
    $checks = ConvertFrom-NessusAuditFile -Path $AuditPath
    $inputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($AuditPath)
} else {
    if (-not (Test-Path -LiteralPath $ChecksPath)) {
        throw "Checks file not found: $ChecksPath"
    }
    $checks = Import-Csv -LiteralPath $ChecksPath
    $inputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ChecksPath)
}

if (-not [string]::IsNullOrWhiteSpace($ExportChecksPath)) {
    $checks | Export-Csv -LiteralPath $ExportChecksPath -NoTypeInformation -Encoding UTF8
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot ("{0}_results_{1}.csv" -f $inputBaseName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$results = foreach ($check in $checks) {
    $checkName = "{0} {1}" -f $check.Id, $check.Title

    # Catalog opt-out: keep the row but skip evaluation entirely.
    if (Test-ChecklistExcluded $check) {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = 'Excluded by catalog (Checklist=0).'
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
        continue
    }

    $manualReason = [string](Get-ObjectPropertyValue -Object $check -Name 'ManualReason')

    if ($check.Method -eq 'Manual') {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = if ([string]::IsNullOrWhiteSpace($manualReason)) { 'Manual review required' } else { $manualReason }
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
        continue
    }

    try {
        $result = Invoke-NessusCheck $check
        $status = if ($null -eq $result.Pass) { 'Manual' } elseif ($result.Pass) { 'Pass' } else { 'Fail' }
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = $result.Actual
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = $status
        }
    } catch {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = "Error: $($_.Exception.Message)"
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
    }
}

$results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote Nessus audit results to: $OutputPath"

if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $htmlInputLabel = $AuditPath
    if ([string]::IsNullOrWhiteSpace($htmlInputLabel)) { $htmlInputLabel = $ChecksPath }
    Export-AuditHtmlReport -Results $results -Path $HtmlPath -Title $ReportTitle -Company $CompanyName -Client $ClientName -Assessor $AssessorName -InputLabel $htmlInputLabel -LogoFile $LogoPath
    Write-Host "Wrote HTML report to: $HtmlPath"
}
