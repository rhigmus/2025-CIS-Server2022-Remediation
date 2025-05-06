function Invoke-Control25357 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25357: Status of Block abuse of exploited vulnerable signed drivers ASR rule (56a863a9-875e-4185-98a7-b882c64b5ce5)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25357"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25357: Block abuse of exploited vulnerable signed drivers ASR rule"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "56a863a9-875e-4185-98a7-b882c64b5ce5" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block abuse of vulnerable signed drivers."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25357: $_"
}
}
