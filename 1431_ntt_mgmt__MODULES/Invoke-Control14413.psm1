function Invoke-Control14413 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 14413: Status of the Configure detection for potentially unwanted applications setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 14413"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 14413: Status of the Configure detection for potentially unwanted applications setting"
        try {
            # Enable PUA (Potentially Unwanted Application) Protection
            Set-MpPreference -PUAProtection Enabled
            $cmdOutput = "Enabled detection for potentially unwanted applications (PUAProtection)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 14413: $_"
}
