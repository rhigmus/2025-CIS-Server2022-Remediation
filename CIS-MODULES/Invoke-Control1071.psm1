function Invoke-Control1071 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1071: Status of the Minimum Password Length setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1071"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1071"
        try {
            secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
            (Get-Content "$env:TEMP\secpol.cfg").replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 14") | Set-Content "$env:TEMP\secpol.cfg"
            secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
            Remove-Item "$env:TEMP\secpol.cfg","$env:TEMP\secedit.sdb" -Force
            $cmdOutput = "Set minimum password length to 14 characters."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1071: $_"
}
