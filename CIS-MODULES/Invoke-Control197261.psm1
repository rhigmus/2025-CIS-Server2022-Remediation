function Invoke-Control197261 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 19.7.26.1: Status of the Prevent users from sharing files within their profile setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 19.7.26.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 19.7.26.1: Status of the Prevent users from sharing files within their profile setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set NoInplaceSharing to 1 to prevent users from sharing files within their profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 19.7.26.1: $_"
}
}
