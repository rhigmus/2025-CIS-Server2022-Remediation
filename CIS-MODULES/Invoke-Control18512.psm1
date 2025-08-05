function Invoke-Control18512 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.5.12: Status of the MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.5.12"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.5.12"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90 -Type DWord
            $cmdOutput = "Set security log warning level to 90%"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.5.12: $_"
}
}
