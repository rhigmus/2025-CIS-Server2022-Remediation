function Invoke-Control1848 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.4.8: Status of the WDigest Authentication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.4.8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.4.8: WDigest Authentication setting"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
            $cmdOutput = "Disabled WDigest storing plaintext credentials in memory"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.4.8: $_"
}
}
