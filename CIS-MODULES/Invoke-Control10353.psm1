function Invoke-Control10353 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10353: Status of the Turn off Microsoft consumer experiences setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10353"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10353"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Turned off Microsoft consumer experiences."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10353: $_"
}
}
