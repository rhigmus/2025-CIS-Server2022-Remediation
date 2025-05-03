function Invoke-Control25902 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25902: Status of Enable App Installer Hash Override setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25902"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25902"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled App Installer hash override."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25902: $_"
}
