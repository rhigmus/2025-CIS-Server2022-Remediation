function Invoke-Control23206 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23206: Status of the Allow Diagnostic Data setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23206"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23206: Status of the Allow Diagnostic Data setting"
        try {
            # Set Diagnostic Data level to 0 (Required) or 1 (Basic), per CIS recommendations
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Set AllowTelemetry to 0 under HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23206: $_"
}
}
