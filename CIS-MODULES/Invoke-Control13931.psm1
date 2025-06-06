function Invoke-Control13931 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13931: Status of Prevent users and apps from accessing dangerous websites setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13931"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13931"
        try {
            Set-MpPreference -EnableNetworkProtection Enabled
            $cmdOutput = "Enabled Windows Defender Network Protection (blocks dangerous websites)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13931: $_"
}
}
