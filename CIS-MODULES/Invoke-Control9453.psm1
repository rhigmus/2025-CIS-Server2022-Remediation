function Invoke-Control9453 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9453: Status of Scan removable drives (Windows Defender) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9453"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9453: Scan removable drives"
        try {
            Set-MpPreference -DisableRemovableDriveScanning $false
            $cmdOutput = "Enabled scanning of removable drives (DisableRemovableDriveScanning = false)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9453: $_"
}
