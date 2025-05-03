function Invoke-Control14883 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 14883: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 14883"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 14883: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "26190899-1602-49e8-8b27-eb1d0a1ce869" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Executed remediation step for Control ID 14883"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 14883: $_"
}
