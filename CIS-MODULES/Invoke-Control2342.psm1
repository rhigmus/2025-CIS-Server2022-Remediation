function Invoke-Control2342 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2342: Status of the Account Lockout Threshold setting (invalid login attempts)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2342"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2342: Status of the Account Lockout Threshold setting (invalid login attempts)"
        try {
            # Set Account Lockout Threshold
            # Example: Lock account after 5 invalid attempts (CIS typically recommends 5 or fewer)
            net accounts /lockoutthreshold:5
            
            $cmdOutput = "Set Account Lockout Threshold to 5 invalid login attempts."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2342: $_"
}
