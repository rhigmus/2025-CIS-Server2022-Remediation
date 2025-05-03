function Invoke-Control23129 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23129: Status of the Disable OneSettings Downloads setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23129"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23129: Status of the Disable OneSettings Downloads setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 23129"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23129: $_"
}
