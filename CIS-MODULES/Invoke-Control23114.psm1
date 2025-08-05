function Invoke-Control23114 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.4: Configure Network Security: Configure encryption types allowed for Kerberos"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.4: Configure Network Security: Configure encryption types allowed for Kerberos"
        try {
            # Configure allowed encryption types for Kerberos (AES256, AES128, RC4)
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x80000003
            $cmdOutput = "Executed remediation: Configured AES256, AES128, and RC4 encryption types for Kerberos"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.4: $_"
}
}
