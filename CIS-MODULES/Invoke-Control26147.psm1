function Invoke-Control26147 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26147: Status of Configure password backup directory setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26147"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26147: Configure password backup directory"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "PasswordBackupDirectory" -PropertyType String -Value "None" -Force | Out-Null
            $cmdOutput = "Set PasswordBackupDirectory to 'None' to disable cloud password backup."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26147: $_"
}
}
