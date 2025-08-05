function Invoke-Control181072 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.7.2: Status of the default behavior for AutoRun"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.7.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.7.2"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set default behavior for AutoRun to disabled."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.7.2: $_"
}
}
