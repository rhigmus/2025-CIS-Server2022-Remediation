function Invoke-Control1810154 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.15.4: Status of the Do not show feedback notifications setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.15.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.15.4: Disable feedback notifications"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set DoNotShowFeedbackNotifications to 1 to disable feedback prompts."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.15.4: $_"
}
}
