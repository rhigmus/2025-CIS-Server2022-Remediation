function Invoke-Control13923 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13923: Block Office applications from injecting code into other processes ASR rule"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13923"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13923"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block Office applications from injecting code (ID: 75668C1F...)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13923: $_"
}
