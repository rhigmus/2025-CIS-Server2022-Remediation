function Invoke-Control2392 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.9.2: Status of the Microsoft network server: Digitally sign communication (always) setting (SMB)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.9.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.9.2"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
            $cmdOutput = "Enforced SMB signing: Digitally sign communication (always) = Enabled"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.9.2: $_"
}
}
