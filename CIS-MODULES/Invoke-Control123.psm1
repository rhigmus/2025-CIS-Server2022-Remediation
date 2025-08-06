function Invoke-Control123 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1.2.3: Status of the 'Allow Administrator account lockout' setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1.2.3"
            return
        }
    }

    Write-Log "User approved remediation for Control ID 1.2.3: Status of the 'Allow Administrator account lockout' setting"
    try {
        # Enable Administrator account lockout via local security policy (secedit method)
        $tempPath = "$env:TEMP\secpol.inf"
        $dbPath = "$env:TEMP\secedit.sdb"

        # Export current policy
        secedit /export /cfg $tempPath | Out-Null

        # Replace or insert the setting
        $content = Get-Content $tempPath
        if ($content -match '^AllowAdministratorLockout\s*=') {
            $content = $content -replace '^AllowAdministratorLockout\s*=.*', 'AllowAdministratorLockout = 1'
        } else {
            $content += "`n[System Access]"
            $content += 'AllowAdministratorLockout = 1'
        }
        $content | Set-Content $tempPath

        # Apply updated policy
        secedit /configure /db $dbPath /cfg $tempPath /areas SECURITYPOLICY | Out-Null

        # Clean up
        Remove-Item $tempPath, $dbPath -Force

        $cmdOutput = "Enabled Administrator account lockout via local security policy"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1.2.3: $_"
    }
}