function Invoke-Control17241 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17241: Configure Minimize the number of simultaneous connections to the Internet or a Windows Domain Prevent Wi-Fi when on Ethernet."
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17241"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17241"
        try {
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3 -Type DWord
            $cmdOutput = "Set to prevent Wi-Fi connections when Ethernet is connected (MinimizeConnections = 3)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17241: $_"
}
}
