function Invoke-Control8145 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8145: Status of the Security Options Interactive logon: Machine inactivity limit setting (seconds)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8145"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8145: Interactive logon inactivity timeout"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -PropertyType DWord -Value 900 -Force | Out-Null
            $cmdOutput = "Set machine inactivity limit to 900 seconds (15 minutes)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8145: $_"
}
