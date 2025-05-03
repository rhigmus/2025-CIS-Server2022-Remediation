function Invoke-Control2343 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2343: Status of the Reset Account Lockout Counter After setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2343"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2343: Status of the Reset Account Lockout Counter After setting"
        try {
            # Set reset account lockout counter time (in minutes)
            # Example: 15 minutes (CIS benchmark typically recommends this)
            net accounts /lockoutwindow:15
    
            $cmdOutput = "Set Account Lockout Counter Reset After to 15 minutes."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2343: $_"
}
