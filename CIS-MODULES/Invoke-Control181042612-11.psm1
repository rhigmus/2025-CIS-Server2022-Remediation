function Invoke-Control181042612-11 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-11: Status of Block Adobe Reader from creating child processes ASR rule (7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-11"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-11"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "ASR rule 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c enabled for Adobe Reader child process blocking"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-11: $_"
}
}
