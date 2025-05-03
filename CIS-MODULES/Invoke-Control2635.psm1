function Invoke-Control2635 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2635: Status of the Set Client Connection Encryption Level setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2635"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2635"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3 -Type DWord
            $cmdOutput = "Set Client Connection Encryption Level to High (MinEncryptionLevel = 3)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2635: $_"
}
