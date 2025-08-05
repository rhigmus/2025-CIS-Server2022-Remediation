function Invoke-Control18102522 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.25.2.2: Status of the Security: Maximum log size setting (in KB)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.25.2.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.25.2.2: Status of the Security: Maximum log size setting (in KB)"
        try {
            # Set Security event log maximum size (example: 196608 KB = 192 MB)
            wevtutil sl Security /ms:196608
    
            $cmdOutput = "Set Security event log maximum size to 192 MB (196608 KB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.25.2.2: $_"
}
}
