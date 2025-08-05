function Invoke-Control2375 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.7.5: Status of logon banner title setting (Legal Notice)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.7.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.7.5: Status of logon banner title setting (Legal Notice)"
        try {
            # Set the logon banner title (Legal Notice) in the registry
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "Legal Notice"
            $cmdOutput = "Executed remediation: Set logon banner title to 'Legal Notice'"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.7.5: $_"
}
}
