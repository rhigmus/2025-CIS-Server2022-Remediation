function Invoke-Control1810152 {
    <#
    .SYNOPSIS
    CIS 18.10.15.2 - Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'

    .DESCRIPTION
    Prevents the enumeration of admin accounts when a user attempts to elevate an application.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v1.0.0 - 18.10.15.2
    Registry Path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI
    Value Name: EnumerateAdministrators
    Expected Value: 0 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    $ValueName = "EnumerateAdministrators"
    $ExpectedValue = 0

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.10.15.2: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if ($Apply) {
            try {
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }

                Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
                Write-Host "[+] 18.10.15.2: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            } catch {
                Write-Host "[!] 18.10.15.2: Failed to apply remediation: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[+] 18.10.15.2: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}
