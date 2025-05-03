function Invoke-Control22305 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 22305: Enable file hash computation feature"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 22305"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 22305"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableFileHashComputation" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled file hash computation feature."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 22305: $_"
}
