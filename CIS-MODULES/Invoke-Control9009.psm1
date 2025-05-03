function Invoke-Control9009 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9009: Status of the Allow Microsoft accounts to be optional setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9009"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9009: Allow Microsoft accounts to be optional"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set MSAOptional to 1 to allow Microsoft accounts to be optional."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9009: $_"
}
