function Invoke-Control1810163 {
    <#
    .SYNOPSIS
    CIS 18.10.16.3 - Ensure 'Disable OneSettings Downloads' is set to 'Enabled'

    .DESCRIPTION
    Disables connections to the OneSettings service to download configuration settings.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v1.0.0 - 18.10.16.3
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    Value Name: DisableOneSettingsDownloads
    Expected Value: 1 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $ValueName = "DisableOneSettingsDownloads"
    $ExpectedValue = 1

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.10.16.3: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if ($Apply) {
            try {
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }

                Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
                Write-Host "[+] 18.10.16.3: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            } catch {
                Write-Host "[!] 18.10.16.3: Failed to apply remediation: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[+] 18.10.16.3: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}
