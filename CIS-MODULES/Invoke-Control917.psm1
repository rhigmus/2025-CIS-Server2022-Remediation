function Invoke-Control917 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.1.7: Status of the Windows Firewall: Log Successful Connections (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.1.7"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.1.7: Status of the Windows Firewall: Log Successful Connections (Domain) setting"
        try {
            # Enable logging of successful connections for the Domain profile
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set LogSuccessfulConnections to 1 under DomainProfile successfully."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.1.7: $_"
}
}
