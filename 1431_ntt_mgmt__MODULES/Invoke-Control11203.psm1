function Invoke-Control11203 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11203: Status of the Do not suggest third-party content in Windows spotlight setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11203"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11203: Disable third-party content in Spotlight"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled third-party suggestions in Windows Spotlight."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11203: $_"
}
