function Invoke-Control2311 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.1.1: Status of the Security Options Accounts: Block Microsoft accounts setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.1.1: Status of the Security Options Accounts: Block Microsoft accounts setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 2.3.1.1"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.1.1: $_"
}
}
