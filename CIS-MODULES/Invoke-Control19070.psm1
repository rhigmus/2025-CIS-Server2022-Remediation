function Invoke-Control19070 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 19070: Status of the Point and Print Restrictions: When installing drivers for a new connection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 19070"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 19070: Point and Print Restrictions"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Configured Point and Print: driver installs require elevation (NoWarningNoElevationOnInstall set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 19070: $_"
}
