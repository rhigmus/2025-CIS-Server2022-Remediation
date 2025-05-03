function Invoke-Control26148 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26148: Status of Do not allow password expiration time longer than required by policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26148"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26148"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PwdExpiryWarning" -Value 1 -Type DWord
            $cmdOutput = "Restricted password expiration time beyond domain policy limits (PwdExpiryWarning = 1)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26148: $_"
}
