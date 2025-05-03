function Invoke-Control10098 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10098: Status of the Allow Input Personalization setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10098"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10098: Status of the Allow Input Personalization setting"
        try {
            # Disable Input Personalization
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Value 0 -Force | Out-Null
    
            $cmdOutput = "Disabled Input Personalization by setting AllowInputPersonalization to 0, and restricted text/ink collection."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10098: $_"
}
