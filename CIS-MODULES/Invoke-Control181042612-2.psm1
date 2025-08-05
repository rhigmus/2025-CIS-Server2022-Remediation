function Invoke-Control181042612-2 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-2: Status of Block all Office applications from creating child processes ASR rule (D4F940AB-401B-4EFC-AADC-AD5F3C50688A)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-2 - Office Apps child processes D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block all Office apps from creating child processes"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-2 [D4F940AB-401B-4EFC-AADC-AD5F3C50688A]: $_"
}
}
