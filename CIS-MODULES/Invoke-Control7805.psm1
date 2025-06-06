function Invoke-Control7805 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 7805: Status of Windows Automatic Updates (WSUS) setting ( NoAutoUpdate )"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 7805"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 7805: WSUS setting NoAutoUpdate"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Set NoAutoUpdate to 0 to ensure automatic updates are enabled."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 7805: $_"
}
}
