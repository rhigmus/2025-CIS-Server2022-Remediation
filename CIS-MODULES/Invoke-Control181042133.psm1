function Invoke-Control181042133 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.13.3: Status of Windows Defender - Turn on e-mail scanning setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.13.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.13.3: Enable Defender email scanning"
        try {
            Set-MpPreference -DisableEmailScanning $false
            $cmdOutput = "Enabled e-mail scanning in Windows Defender (DisableEmailScanning = False)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.13.3: $_"
}
}
