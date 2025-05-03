function Invoke-Control26149 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26149: Status of password (PasswordAgeDays) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26149"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26149: Maximum password age"
        try {
            net accounts /maxpwage:90
            $cmdOutput = "Set maximum password age to 90 days."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26149: $_"
}
