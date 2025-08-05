function Invoke-Control1810171 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.17.1: Status of Enable App Installer setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.17.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.17.1"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableAppInstaller" -Value 0 -Type DWord
            $cmdOutput = "Disabled App Installer (EnableAppInstaller = 0)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.17.1: $_"
}
}
