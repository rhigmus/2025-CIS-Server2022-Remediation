function Invoke-Control23138 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23138: Status of the Turn off Spotlight collection on Desktop setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23138"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23138: Turn off Spotlight collection on Desktop"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled Windows Spotlight collection on the desktop background."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23138: $_"
}
