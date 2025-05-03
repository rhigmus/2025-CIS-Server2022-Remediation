function Invoke-Control1390 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1390: Status of the Network Security: Minimum session security for NTLM SSP based (including secure RPC) servers setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1390"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1390: NTLM SSP minimum session security for servers"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
            $cmdOutput = "Configured NTLM SSP server minimum session security to require NTLMv2, 128-bit encryption, and message integrity"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1390: $_"
}
