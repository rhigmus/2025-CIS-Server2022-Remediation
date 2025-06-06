function Invoke-Control25903 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25903: Status of Enable App Installer ms-appinstaller protocol setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25903"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25903"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord
            $cmdOutput = "Disabled App Installer ms-appinstaller protocol (EnableMSAppInstallerProtocol = 0)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25903: $_"
}
}
