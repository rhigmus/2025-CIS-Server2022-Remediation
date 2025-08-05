function Invoke-Control181056395 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.56.3.9.5: Status of the Set Client Connection Encryption Level setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.56.3.9.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.56.3.9.5"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3 -Type DWord
            $cmdOutput = "Set Client Connection Encryption Level to High (MinEncryptionLevel = 3)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.56.3.9.5: $_"
}
}
