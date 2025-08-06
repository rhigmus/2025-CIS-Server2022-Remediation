function Invoke-Control1810167 {
    <#
    .SYNOPSIS
    CIS 18.10.16.7 - Ensure 'Limit Dump Collection' is set to 'Enabled'

    .DESCRIPTION
    Configures Windows to limit the type of memory dumps that can be collected and transmitted.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v4.0.0 - 18.10.16.7
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    Value Name: LimitDumpCollection
    Expected Value: 1 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $ValueName = "LimitDumpCollection"
    $ExpectedValue = 1

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.10.16.7: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if ($Apply) {
            try {
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }

                Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
                Write-Host "[+] 18.10.16.7: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            } catch {
                Write-Host "[!] 18.10.16.7: Failed to apply remediation: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[+] 18.10.16.7: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}