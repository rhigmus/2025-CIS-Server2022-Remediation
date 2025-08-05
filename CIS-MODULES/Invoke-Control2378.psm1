function Invoke-Control2378 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.7.8: Status of the Interactive Logon: Require Domain Controller authentication to unlock workstation setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.7.8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.7.8: Require DC authentication to unlock workstation"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set ForceUnlockLogon to 1 to require DC authentication when unlocking."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.7.8: $_"
}
}
