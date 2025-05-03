function Invoke-Control9404 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9404: Status of the Prevent the usage of OneDrive for file storage (Skydrive) group policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9404"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9404: Prevent OneDrive usage"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled OneDrive file storage integration (DisableFileSync set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9404: $_"
}
