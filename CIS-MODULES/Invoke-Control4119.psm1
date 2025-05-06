function Invoke-Control4119 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4119: Status of the Allow indexing of encrypted files setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4119"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4119: Status of the Allow indexing of encrypted files setting"
        try {
            # Disable indexing of encrypted files
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -PropertyType DWord -Value 0 -Force | Out-Null
    
            $cmdOutput = "Disabled AllowIndexingEncryptedStoresOrItems (set to 0) under HKLM:\Software\Policies\Microsoft\Windows\Windows Search."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4119: $_"
}
}
