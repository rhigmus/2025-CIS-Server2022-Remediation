function Invoke-Control18104216 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.16: Status of the Configure detection for potentially unwanted applications setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.16"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.16: Status of the Configure detection for potentially unwanted applications setting"
        try {
            # Enable PUA (Potentially Unwanted Application) Protection
            Set-MpPreference -PUAProtection Enabled
            $cmdOutput = "Enabled detection for potentially unwanted applications (PUAProtection)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.16: $_"
}
}
