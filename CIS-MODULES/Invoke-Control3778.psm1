function Invoke-Control3778 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3778: Status of the contents of the login banner (Windows/Unix/Linux)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3778"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3778: Status of the contents of the login banner (Windows/Unix/Linux)"
        try {
            # Set the legal banner message and caption
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -PropertyType String -Value "WARNING" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -PropertyType String -Value "This system is for authorized use only. Unauthorized access is prohibited and may be subject to disciplinary action and criminal prosecution." -Force | Out-Null
    
            $cmdOutput = "Set login banner caption and text for LegalNotice."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3778: $_"
}
}
