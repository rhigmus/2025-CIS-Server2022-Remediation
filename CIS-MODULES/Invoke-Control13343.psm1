function Invoke-Control13343 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13343: Status of the Configure Windows Defender SmartScreen - Pick one of the following setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13343"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13343: Configure Windows Defender SmartScreen"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -PropertyType String -Value "Warn" -Force | Out-Null
            $cmdOutput = "Enabled SmartScreen with 'Warn' level (EnableSmartScreen = 1, ShellSmartScreenLevel = 'Warn')."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13343: $_"
}
