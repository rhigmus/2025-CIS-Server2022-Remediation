function Invoke-Control181042612-4 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-4: Status of Block execution of potentially obfuscated scripts ASR rule (5BEB7EFE-FD9A-4556-801D-275E5FFC04CC)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-4 - Block execution of potentially obfuscated scripts ASR rule (5BEB7EFE-FD9A-4556-801D-275E5FFC04CC)"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block execution of potentially obfuscated scripts"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-4 [5beb7efe-fd9a-4556-801d-275e5ffc04cc]: $_"
}
}
