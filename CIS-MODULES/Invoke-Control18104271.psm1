function Invoke-Control18104271 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.7.1: Enable file hash computation feature"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.7.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.7.1"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableFileHashComputation" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled file hash computation feature."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.7.1: $_"
}
}
