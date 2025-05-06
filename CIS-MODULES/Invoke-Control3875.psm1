function Invoke-Control3875 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3875: Status of the Do not allow drive redirection setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3875"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3875: Disable drive redirection in RDP"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled drive redirection (fDisableCdm = 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3875: $_"
}
}
