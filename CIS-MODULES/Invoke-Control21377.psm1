function Invoke-Control21377 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 21377: Status of Block persistence through WMI event subscription ASR rule (e6db77e5-3df2-4cf1-b95a-636979351e5b)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 21377"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 21377: Status of Block persistence through WMI event subscription ASR rule"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "e6db77e5-3df2-4cf1-b95a-636979351e5b" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block persistence through WMI event subscription"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 21377: $_"
}
}
