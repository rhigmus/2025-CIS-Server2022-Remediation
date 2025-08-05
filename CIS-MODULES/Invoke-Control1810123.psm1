function Invoke-Control1810123 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.12.3: Status of the Turn off Microsoft consumer experiences setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.12.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.12.3"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Turned off Microsoft consumer experiences."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.12.3: $_"
}
}
