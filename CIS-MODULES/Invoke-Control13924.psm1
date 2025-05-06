function Invoke-Control13924 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13924: Status of Block all Office applications from creating child processes ASR rule (D4F940AB-401B-4EFC-AADC-AD5F3C50688A)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13924"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13924"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block all Office apps from creating child processes"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13924: $_"
}
}
