function Invoke-Control19071 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 19071: Status of the Point and Print Restrictions: When updating drivers for an existing connection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 19071"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 19071"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -Value 0 -Type DWord
            $cmdOutput = "Set NoWarningNoElevationOnUpdate = 0 (Elevation prompt required when updating drivers)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 19071: $_"
}
