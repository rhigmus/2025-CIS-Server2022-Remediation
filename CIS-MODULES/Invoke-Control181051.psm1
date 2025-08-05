function Invoke-Control181051 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.5.1: Status of the Allow Microsoft accounts to be optional setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.5.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.5.1: Allow Microsoft accounts to be optional"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set MSAOptional to 1 to allow Microsoft accounts to be optional."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.5.1: $_"
}
}
