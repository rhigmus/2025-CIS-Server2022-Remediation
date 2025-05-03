function Invoke-Control13928 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13928: Status of Block executable content from email client and webmail ASR rule (BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13928"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13928"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block executable content from email client and webmail"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13928: $_"
}
