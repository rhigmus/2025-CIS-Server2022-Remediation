function Invoke-Control181042612-7 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-7: Status of Block untrusted and unsigned processes that run from USB ASR rule (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-7"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-7: USB ASR rule"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block untrusted/unsigned USB processes"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-7: $_"
}
}
