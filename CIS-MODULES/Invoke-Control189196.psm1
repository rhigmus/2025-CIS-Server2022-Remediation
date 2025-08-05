function Invoke-Control189196 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.19.6: Status of the Continue experiences on this device setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.19.6"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.19.6: Status of the Continue experiences on this device setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled cross-device experience features (EnableCdp set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.19.6: $_"
}
}
