function Invoke-Control13926 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13926: Status of Block execution of potentially obfuscated scripts ASR rule (5BEB7EFE-FD9A-4556-801D-275E5FFC04CC)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13926"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13926"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block execution of potentially obfuscated scripts"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13926: $_"
}
