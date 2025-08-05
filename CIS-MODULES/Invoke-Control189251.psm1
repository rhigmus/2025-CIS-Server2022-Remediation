function Invoke-Control189251 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.25.1: Status of Configure password backup directory setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.25.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.25.1: Configure password backup directory"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "PasswordBackupDirectory" -PropertyType String -Value "None" -Force | Out-Null
            $cmdOutput = "Set PasswordBackupDirectory to 'None' to disable cloud password backup."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.25.1: $_"
}
}
