function Invoke-Control1169 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1169: Status of the MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1169"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1169: AutoAdminLogon setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -PropertyType String -Value "0" -Force | Out-Null
            $cmdOutput = "Disabled automatic logon (AutoAdminLogon set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1169: $_"
}
}
