function Invoke-Control2616 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2616: Status of the Prohibit installation and configuration of Network Bridge on the DNS domain network setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2616"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2616"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Prohibited installation/configuration of Network Bridge on DNS domain network."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2616: $_"
}
