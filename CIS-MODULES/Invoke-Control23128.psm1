function Invoke-Control23128 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23128: Status of the Turn off cloud consumer account state content setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23128"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23128: Disable cloud consumer account state content"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord
            $cmdOutput = "Disabled cloud consumer account state content"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23128: $_"
}
