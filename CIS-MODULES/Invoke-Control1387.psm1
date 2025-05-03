function Invoke-Control1387 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1387: Status of the Network Security: LAN Manager Authentication Level setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1387"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1387"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
            $cmdOutput = "Set LAN Manager Authentication Level to 'Send NTLMv2 response only. Refuse LM and NTLM'"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1387: $_"
}
