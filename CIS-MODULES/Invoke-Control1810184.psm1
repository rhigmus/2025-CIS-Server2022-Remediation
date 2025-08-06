function Invoke-Control1810184 {
    <#
    .SYNOPSIS
    CIS 18.10.18.4 - Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled'

    .DESCRIPTION
    Prevents users from overriding malware scans when installing local archive files via App Installer with command-line arguments.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v140.0 - 18.10.18.4
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller
    Value Name: EnableLocalArchiveMalwareScanOverride
    Expected Value: 0 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
    $ValueName = "EnableLocalArchiveMalwareScanOverride"
    $ExpectedValue = 0

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.10.18.4: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if ($Apply) {
            try {
                if (-not (Test-Path $RegPath)) {
                    New-Item -Path $RegPath -Force | Out-Null
                }

                Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
                Write-Host "[+] 18.10.18.4: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            } catch {
                Write-Host "[!] 18.10.18.4: Failed to apply remediation: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[+] 18.10.18.4: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}