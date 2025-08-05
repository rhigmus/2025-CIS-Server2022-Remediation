function Invoke-Control18710 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.7.10: Status of the Point and Print Restrictions: When installing drivers for a new connection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.7.10"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.7.10: Point and Print Restrictions"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Configured Point and Print: driver installs require elevation (NoWarningNoElevationOnInstall set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.7.10: $_"
}
}
