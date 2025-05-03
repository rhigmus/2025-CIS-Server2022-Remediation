# Configuration
$sourceFile = "/home/rstark-admin/CIS-Modules/remediate_1431_ntt_mgmt_2.ps1"
$outputFolder = "/home/rstark-admin/CIS-Modules/1431_ntt_mgmt__MODULES"

# Ensure output folder exists
if (!(Test-Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# Read source
$lines = Get-Content $sourceFile
$blocks = @()
$buffer = @()
$inBlock = $false

foreach ($line in $lines) {
    if ($line -match '^Write-Host "\`nControl ID (\d+):') {
        if ($inBlock -and $buffer.Count -gt 0) {
            $blocks += ,@($buffer)
            $buffer = @()
        }
        $inBlock = $true
    }

    if ($inBlock) {
        $buffer += $line
        if ($line -match '^} else \{$') {
            $buffer += $lines[$lines.IndexOf($line) + 1]
            $buffer += $lines[$lines.IndexOf($line) + 2]
            $blocks += ,@($buffer)
            $buffer = @()
            $inBlock = $false
        }
    }
}

# Template for each function
function Get-FunctionTemplate {
    param($controlId, $blockContent)
    return @"
function Invoke-Control$controlId {
    param([bool]`$Apply = `$false)

$blockContent
}
"@
}

# Create a file per block
foreach ($block in $blocks) {
    $headerLine = $block[0]
    if ($headerLine -match 'Control ID (\d+):') {
        $controlId = $matches[1]

        # Adjust block content to add Apply check
        $body = @()
        $skip = $false
        foreach ($line in $block) {
            if ($line -match '^\s*\$confirm\s*=\s*Read-Host') {
                $body += '    if (-not $Apply) {'
                $body += "        $line"
                $body += '        if ($confirm -ne "y") {'
                $body += '            Write-Log "User skipped remediation for Control ID ' + $controlID + '"'
                $body += '            return'
                $body += '        }'
                $body += '    }'
                $skip = $true
            } elseif ($skip -and $line -match '^\s*if\s*\(\$confirm\s*-eq\s*"y"\)') {
                # skip this line
                continue
            } elseif ($skip -and $line -match '^\s*} else {') {
                # skip else block start
                continue
            } elseif ($skip -and $line -match '^\s*Write-Log "User skipped remediation for Control ID') {
                # skip user skip log
                continue
            } elseif ($skip -and $line -match '^\s*}$') {
                # skip closing brace
                continue
            } else {
                $body += "    $line"
            }
        }

        $functionCode = Get-FunctionTemplate -controlId $controlId -blockContent ($body -join "`n")
        $outFile = Join-Path $outputFolder "Invoke-Control$controlId.psm1"
        $functionCode | Set-Content -Path $outFile -Encoding UTF8
        Write-Host "Module written: $outFile"
    }
}
