function Invoke-Control181042612-9 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-9: Block Office applications from creating executable content ASR rule"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-9"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-9"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "3B576869-A4EC-4529-8536-B80A7769E899" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block Office apps from creating executables (ID: 3B576869...)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-9: $_"
}
}
