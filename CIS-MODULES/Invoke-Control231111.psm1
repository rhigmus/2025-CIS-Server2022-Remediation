function Invoke-Control231111 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.11: Status Network Security:Restrict NTLM: Audit Incoming NTLM Traffic setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.11"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.11: Audit Incoming NTLM Traffic"
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -PropertyType DWord -Value 2 -Force | Out-Null
            $cmdOutput = "Set AuditReceivingNTLMTraffic to 2 (audit all incoming NTLM traffic)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.11: $_"
}
}
