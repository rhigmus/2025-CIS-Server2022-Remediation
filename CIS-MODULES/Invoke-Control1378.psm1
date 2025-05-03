function Invoke-Control1378 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1378: Status of the Interactive Logon: Smart Card Removal Behavior setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1378"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1378: Smart Card Removal Behavior"
        try {
            secedit /export /cfg C:\Windows\Temp\secpol.cfg
            (Get-Content C:\Windows\Temp\secpol.cfg).replace("ScRemoveOption = 0", "ScRemoveOption = 1") | Set-Content C:\Windows\Temp\secpol.cfg
            secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
            Remove-Item C:\Windows\Temp\secpol.cfg
            $cmdOutput = "Set Smart Card Removal Behavior to lock the workstation (ScRemoveOption = 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1378: $_"
}
