function Invoke-Control8176 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8176: Status of the Do not enumerate connected users on domain-joined computers setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8176"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8176: Status of the Do not enumerate connected users on domain-joined computers setting"
        try {
            # Set DoNotEnumerateConnectedUsers to 1 (enabled)
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontEnumerateConnectedUsers" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Set DontEnumerateConnectedUsers to 1 under HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8176: $_"
}
