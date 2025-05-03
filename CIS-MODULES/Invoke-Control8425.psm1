function Invoke-Control8425 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8425: Status of Do not display the password reveal button"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8425"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8425: Status of Do not display the password reveal button"
        try {
            # Disable the password reveal button
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set DisablePasswordReveal to 1 under HKLM:\Software\Policies\Microsoft\Windows\CredUI"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8425: $_"
}
