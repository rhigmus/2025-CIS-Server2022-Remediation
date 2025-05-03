function Invoke-Control8274 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8274: Status of the Configure Windows Defender SmartScreen setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8274"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8274: Configure Windows Defender SmartScreen"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled SmartScreen (EnableSmartScreen set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8274: $_"
}
