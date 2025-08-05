function Invoke-Control189131 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.13.1: Status of the Boot-Start Driver Initialization Policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.13.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.13.1: Status of the Boot-Start Driver Initialization Policy setting"
        try {
            # Set Boot-Start Driver Initialization Policy to Good and Unknown drivers blocked
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set DriverLoadPolicy to 1 under HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.13.1: $_"
}
}
