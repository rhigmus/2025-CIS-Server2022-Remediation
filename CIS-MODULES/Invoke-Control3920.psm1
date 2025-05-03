function Invoke-Control3920 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3920: Status of the Turn off Internet download for Web publishing and online ordering wizards setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3920"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3920: Disable Internet downloads for publishing/ordering wizards"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled Internet download for Web publishing/ordering wizards (NoWebServices set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3920: $_"
}
