function Invoke-Control10377 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10377: Status of the Use enhanced anti-spoofing when available setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10377"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10377: Use enhanced anti-spoofing"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled enhanced anti-spoofing for facial recognition."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10377: $_"
}
