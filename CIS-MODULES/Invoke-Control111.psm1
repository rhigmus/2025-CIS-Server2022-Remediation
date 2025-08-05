function Invoke-Control111 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1.1.1: Status of the Enforce password history setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1.1.1: Status of the Enforce password history setting"
        try {
            secedit /export /cfg C:\Temp\secpol.cfg
            (Get-Content C:\Temp\secpol.cfg).replace("PasswordHistorySize = 0", "PasswordHistorySize = 24") | Set-Content C:\Temp\secpol.cfg
            secedit /configure /db secedit.sdb /cfg C:\Temp\secpol.cfg /areas SECURITYPOLICY
            Remove-Item C:\Temp\secpol.cfg
            $cmdOutput = "Set Enforce password history to 24 passwords remembered"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1.1.1: $_"
}
}
