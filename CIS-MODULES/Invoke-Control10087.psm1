function Invoke-Control10087 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10087: Status of the Enable Windows NTP Client setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10087"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10087"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord
            $cmdOutput = "Enabled Windows NTP Client"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10087: $_"
}
}
