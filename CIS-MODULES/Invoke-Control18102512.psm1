function Invoke-Control18102512 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.25.1.2: Status of the Application: Maximum log size setting (in KB)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.25.1.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.25.1.2: Status of the Application: Maximum log size setting (in KB)"
        try {
            wevtutil sl Application /ms:32768
            $cmdOutput = "Set Application log maximum size to 32768 KB"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.25.1.2: $_"
}
}
