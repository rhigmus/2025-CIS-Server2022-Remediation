function Invoke-Control8243 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8243: Configure Network Security:Restrict NTLM: Outgoing NTLM traffic to remote servers"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8243"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8243: Restrict outgoing NTLM"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -PropertyType DWord -Value 2 -Force | Out-Null
            $cmdOutput = "Restricted outgoing NTLM traffic to remote servers (Block all = 2)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8243: $_"
}
