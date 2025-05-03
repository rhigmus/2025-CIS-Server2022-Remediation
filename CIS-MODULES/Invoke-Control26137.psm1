function Invoke-Control26137 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26137: Status of Password (PasswordLength) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26137"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26137: Password minimum length"
        try {
            net accounts /minpwlen:14
            $cmdOutput = "Set minimum password length to 14 characters."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26137: $_"
}
