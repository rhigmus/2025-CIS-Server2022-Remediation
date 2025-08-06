function Invoke-Control18112 {
    <#
    .SYNOPSIS
    CIS 18.1.1.2 - Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'

    .DESCRIPTION
    Disables the lock screen slide show and prevents users from enabling it through PC Settings.

    .PARAMETER Apply
    If specified, applies the remediation. Otherwise, only reports non-compliance.

    .NOTES
    Reference: CIS Microsoft Windows Server 2022 Benchmark v4.0.0 - 18.1.1.2
    Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization
    Value Name: NoLockScreenSlideshow
    Expected Value: 1 (REG_DWORD)
    #>

    [CmdletBinding()]
    param (
        [switch]$Apply
    )

    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $ValueName = "NoLockScreenSlideshow"
    $ExpectedValue = 1

    Write-Host "`nControl 18.1.1.2: Prevent enabling lock screen slide show"

    try {
        $actualValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop | Select-Object -ExpandProperty $ValueName
    } catch {
        $actualValue = $null
    }

    if ($actualValue -ne $ExpectedValue) {
        Write-Host "[-] 18.1.1.2: Non-compliant. Current value: $actualValue" -ForegroundColor Yellow

        if (-not $Apply) {
            $confirm = Read-Host "Apply remediation for 18.1.1.2? (y/n)"
            if ($confirm -ne "y") {
                Write-Log "User skipped remediation for Control 18.1.1.2"
                return
            }
        }

        Write-Log "User approved remediation for Control 18.1.1.2"

        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }

            Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
            Write-Host "[+] 18.1.1.2: Remediation applied. Set $ValueName to $ExpectedValue" -ForegroundColor Green
            Write-Log "Successfully remediated 18.1.1.2: Set $ValueName to $ExpectedValue"
        } catch {
            Write-Host "[!] 18.1.1.2: Failed to apply remediation: $_" -ForegroundColor Red
            Write-Log "ERROR applying remediation for 18.1.1.2: $_"
        }
    } else {
        Write-Host "[+] 18.1.1.2: Compliant. Value is already set to $ExpectedValue" -ForegroundColor Green
    }
}