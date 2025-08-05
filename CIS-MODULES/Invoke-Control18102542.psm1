function Invoke-Control18102542 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.25.4.2: Status of the System: Maximum log size setting (in KB)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.25.4.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.25.4.2: Status of the System: Maximum log size setting (in KB)"
        try {
            # Set System event log maximum size (example: 32768 KB = 32 MB, commonly recommended)
            wevtutil sl System /ms:32768
    
            $cmdOutput = "Set System event log maximum size to 32 MB (32768 KB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.25.4.2: $_"
}
}
