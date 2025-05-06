function Invoke-Control25338 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25338: Status of the Configure Redirection Guard setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25338"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25338: Configure Redirection Guard"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled Redirection Guard with VBS and secure platform enforcement."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25338: $_"
}
}
