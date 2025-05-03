function Invoke-Control1183 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1183: Status of the Disable Autorun for all drives setting for the HKLM key"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1183"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1183"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null
            $cmdOutput = "Disabled Autorun for all drives (HKLM)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1183: $_"
}
