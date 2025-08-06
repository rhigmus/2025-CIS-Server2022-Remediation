function Invoke-Control18111 {
    <#
    .SYNOPSIS
    CIS 18.1.1.1 - Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'

    .DESCRIPTION
    Disables the lock screen camera toggle and prevents any camera access from the lock screen by setting NoLockScreenCamera = 1.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v4.0.0 - 18.1.1.1
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization
    Value Name: NoLockScreenCamera
    Expected Value: 1 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $ValueName = "NoLockScreenCamera"
    $ExpectedValue = 1

    Write-Host "`nControl 18.1.1.1: Prevent enabling lock screen camera"

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.1.1.1: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if (-not $Apply) {
            $confirm = Read-Host "Apply remediation for 18.1.1.1? (y/n)"
            if ($confirm -ne "y") {
                Write-Log "User skipped remediation for Control 18.1.1.1"
                return
            }
        }

        Write-Log "User approved remediation for Control 18.1.1.1"

        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }

            Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
            Write-Host "[+] 18.1.1.1: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            Write-Log "Successfully remediated 18.1.1.1: Set $ValueName to $ExpectedValue"
        } catch {
            Write-Host "[!] 18.1.1.1: Failed to apply remediation: $_" -ForegroundColor Red
            Write-Log "ERROR applying remediation for 18.1.1.1: $_"
        }
    } else {
        Write-Host "[+] 18.1.1.1: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}