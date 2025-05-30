function Invoke-Control1172 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1172: Status of the MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1172"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1172: Disable IP Source Routing"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force | Out-Null
            $cmdOutput = "Set DisableIPSourceRouting to 2 (highest protection)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1172: $_"
}
}
