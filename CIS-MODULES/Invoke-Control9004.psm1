function Invoke-Control9004 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9004: Status of the Lock screen slide show setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9004"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9004: Status of the Lock screen slide show setting"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord
            $cmdOutput = "Disabled lock screen slideshow"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9004: $_"
}
