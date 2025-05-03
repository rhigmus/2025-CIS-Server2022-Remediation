function Invoke-Control1193 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1193: Status of the MSS: Allow ICMP redirects to override OSPF generated routes (EnableICMPRedirect) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1193"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1193: MSS - Disable ICMP Redirects"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
            $cmdOutput = "Disabled ICMP redirects from overriding OSPF routes"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1193: $_"
}
