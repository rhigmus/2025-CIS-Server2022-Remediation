function Invoke-Control1810153 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.15.3: Status of the Disable OneSettings Downloads setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.15.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.15.3: Status of the Disable OneSettings Downloads setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 18.10.15.3"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.15.3: $_"
}
}
