function Invoke-Control10370 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10370: Status of the Enable insecure guest logons setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10370"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10370: Disable insecure guest logons"
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled insecure guest logons (AllowInsecureGuestAuth = 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10370: $_"
}
}
