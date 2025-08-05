function Invoke-Control23119 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.9: Status of the Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.9"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.9"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -PropertyType DWord -Value 537395200 -Force | Out-Null
            $cmdOutput = "Set minimum session security for NTLM SSP clients (Require NTLMv2, 128-bit encryption, and signing)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.9: $_"
}
}
