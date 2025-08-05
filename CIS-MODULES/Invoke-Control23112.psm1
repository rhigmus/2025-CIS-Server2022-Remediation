function Invoke-Control23112 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.2: Status of the Network security: Allow LocalSystem NULL session fallback setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.2: Status of the Network security: Allow LocalSystem NULL session fallback setting"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowNullSessionFallback" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 2.3.11.2"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.2: $_"
}
}
