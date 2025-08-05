function Invoke-Control18107521 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.75.2.1: Status of the Configure Windows Defender SmartScreen - Pick one of the following setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.75.2.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.75.2.1: Configure Windows Defender SmartScreen"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -PropertyType String -Value "Warn" -Force | Out-Null
            $cmdOutput = "Enabled SmartScreen with 'Warn' level (EnableSmartScreen = 1, ShellSmartScreenLevel = 'Warn')."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.75.2.1: $_"
}
}
