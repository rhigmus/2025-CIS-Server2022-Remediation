function Invoke-Control1810131 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.13.1: Status of the Require pin for pairing Enabled First Time OR Always setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.13.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.13.1: Require PIN for device pairing"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled PIN requirement for Bluetooth device pairing (RequirePinForPairing set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.13.1: $_"
}
}
