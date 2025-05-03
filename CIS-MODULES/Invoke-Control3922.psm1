function Invoke-Control3922 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3922: Status of the Turn off downloading of print drivers over HTTP setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3922"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3922: Turn off HTTP print driver downloads"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled downloading of print drivers over HTTP (DisableWebPnPDownload set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3922: $_"
}
