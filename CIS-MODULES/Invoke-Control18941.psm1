function Invoke-Control18941 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.4.1: Status of the Encryption Oracle Remediation group policy"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.4.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.4.1: Configure Encryption Oracle Remediation"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Set AllowEncryptionOracle to 0 (Force updated clients only)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.4.1: $_"
}
}
