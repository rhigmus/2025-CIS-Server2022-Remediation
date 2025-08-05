function Invoke-Control181042631 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.3.1: Status of Prevent users and apps from accessing dangerous websites setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.3.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.3.1"
        try {
            Set-MpPreference -EnableNetworkProtection Enabled
            $cmdOutput = "Enabled Windows Defender Network Protection (blocks dangerous websites)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.3.1: $_"
}
}
