function Invoke-Control10348 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10348: Status of the Do not show feedback notifications setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10348"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10348: Disable feedback notifications"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set DoNotShowFeedbackNotifications to 1 to disable feedback prompts."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10348: $_"
}
