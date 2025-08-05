function Invoke-Control116 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1.1.6: Status of the Relax minimum password length limits setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1.1.6"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1.1.6: Status of the Relax minimum password length limits setting"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ScEnableRelaxationOnMinimumPasswordLength" -Value 0 -Type DWord
            $cmdOutput = "Disabled relaxed minimum password length enforcement"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1.1.6: $_"
}
}
