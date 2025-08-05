function Invoke-Control18105622 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.56.2.2: Status of the Do not allow passwords to be saved setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.56.2.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.56.2.2"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord
            $cmdOutput = "Disallowed saving of passwords in RDP sessions (DisablePasswordSaving = 1)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.56.2.2: $_"
}
}
