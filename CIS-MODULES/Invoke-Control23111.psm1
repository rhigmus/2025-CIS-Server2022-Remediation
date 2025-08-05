function Invoke-Control23111 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.1: Status of the Network security: Allow Local System to use computer identity for NTLM setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.1"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowSystemToUseComputerIdentity" -Value 1 -Type DWord
            $cmdOutput = "Enabled Local System use of computer identity for NTLM"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.1: $_"
}
}
