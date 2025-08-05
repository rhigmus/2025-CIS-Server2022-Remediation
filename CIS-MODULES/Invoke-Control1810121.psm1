function Invoke-Control1810121 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.12.1: Status of the Turn off cloud consumer account state content setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.12.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.12.1: Disable cloud consumer account state content"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord
            $cmdOutput = "Disabled cloud consumer account state content"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.12.1: $_"
}
}
