function Invoke-Control1852 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.5.2: Status of the MSS: (DisableIPSourceRoutingIPv6) IP source routing protection level (IPv6)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.5.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.5.2: Disable IPv6 IP source routing"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force | Out-Null
            $cmdOutput = "Set DisableIPSourceRouting (IPv6) to 2 to fully disable source routing."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.5.2: $_"
}
}
