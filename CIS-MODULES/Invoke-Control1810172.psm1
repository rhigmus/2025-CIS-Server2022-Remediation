function Invoke-Control1810172 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.17.2: Status of Enable App Installer Experimental Features setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.17.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.17.2"
        try {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord
            $cmdOutput = "Disabled App Installer Experimental Features"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.17.2: $_"
}
}
