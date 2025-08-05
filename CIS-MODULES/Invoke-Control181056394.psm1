function Invoke-Control181056394 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.56.3.9.4: Status of the Require user authentication for remote connections by using Network Level Authentication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.56.3.9.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.56.3.9.4: Require user authentication for remote connections by using NLA"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled NLA for RDP (UserAuthentication set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.56.3.9.4: $_"
}
}
