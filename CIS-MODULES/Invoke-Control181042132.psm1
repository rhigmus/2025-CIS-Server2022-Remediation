function Invoke-Control181042132 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.13.2: Status of Scan removable drives (Windows Defender) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.13.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.13.2: Scan removable drives"
        try {
            Set-MpPreference -DisableRemovableDriveScanning $false
            $cmdOutput = "Enabled scanning of removable drives (DisableRemovableDriveScanning = false)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.13.2: $_"
}
}
