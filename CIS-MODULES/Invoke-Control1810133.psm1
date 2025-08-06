function Invoke-Control1810133 {
    <#
    .SYNOPSIS
    CIS 18.10.13.3 - Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'

    .DESCRIPTION
    Sets the registry value DisableWindowsConsumerFeatures to 1 to disable Microsoft consumer experiences.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v1.0.0 - 18.10.13.3
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent
    Value Name: DisableWindowsConsumerFeatures
    Expected Value: 1 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $ValueName = "DisableWindowsConsumerFeatures"
    $ExpectedValue = 1

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.10.13.3: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if ($Apply) {
            try {
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }

                Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
                Write-Host "[+] 18.10.13.3: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            } catch {
                Write-Host "[!] 18.10.13.3: Failed to apply remediation: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[+] 18.10.13.3: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}
