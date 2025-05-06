function Invoke-Control5266 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 5266: Status of the Network security: Allow Local System to use computer identity for NTLM setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 5266"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 5266"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowSystemToUseComputerIdentity" -Value 1 -Type DWord
            $cmdOutput = "Enabled Local System use of computer identity for NTLM"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 5266: $_"
}
}
