function Invoke-Control14884 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 14884: Status of Block Adobe Reader from creating child processes ASR rule (7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 14884"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 14884"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "ASR rule 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c enabled for Adobe Reader child process blocking"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 14884: $_"
}
