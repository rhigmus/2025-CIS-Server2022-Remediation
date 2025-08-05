function Invoke-Control18102532 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.25.3.2: Status of the Setup: Maximum Log Size (KB) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.25.3.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.25.3.2: Setup log max size"
        try {
            wevtutil sl Setup /ms:32768
            $cmdOutput = "Set Setup log maximum size to 32768 KB (32 MB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.25.3.2: $_"
}
}
