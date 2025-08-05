function Invoke-Control19781 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 19.7.8.1: Status of the Configure Windows spotlight on Lock Screen setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 19.7.8.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 19.7.8.1"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord
            $cmdOutput = "Disabled Windows Spotlight on Lock Screen (ConfigureWindowsSpotlight = 2)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 19.7.8.1: $_"
}
}
