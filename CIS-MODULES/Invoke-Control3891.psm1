function Invoke-Control3891 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3891: Status of the Always prompt for password upon connection setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3891"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3891: Require password prompt on RDP connection"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Configured Terminal Services to always prompt for password upon connection."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3891: $_"
}
}
