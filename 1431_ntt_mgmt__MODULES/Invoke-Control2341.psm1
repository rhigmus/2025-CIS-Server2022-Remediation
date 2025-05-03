function Invoke-Control2341 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2341: Status of the Account Lockout Duration setting (invalid login attempts)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2341"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2341: Status of the Account Lockout Duration setting (invalid login attempts)"
        try {
            # Set Account Lockout Duration (example: 15 minutes)
            net accounts /lockoutduration:15
    
            $cmdOutput = "Set Account Lockout Duration to 15 minutes."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2341: $_"
}
