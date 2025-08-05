function Invoke-Control181042612-10 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-10: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-10"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-10: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "26190899-1602-49e8-8b27-eb1d0a1ce869" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Executed remediation step for Control ID 18.10.42.6.1.2-10"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-10: $_"
}
}
