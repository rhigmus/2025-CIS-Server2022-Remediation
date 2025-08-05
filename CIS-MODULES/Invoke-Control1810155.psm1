function Invoke-Control1810155 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.15.5: Status of the Enable OneSettings Auditing setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.15.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.15.5: Enable OneSettings Auditing"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled OneSettings auditing (EnableOneSettingsAuditing set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.15.5: $_"
}
}
