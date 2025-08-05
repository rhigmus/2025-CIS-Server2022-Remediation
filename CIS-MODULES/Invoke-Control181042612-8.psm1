function Invoke-Control181042612-8 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-8: Status of Block credential stealing from the Windows local security authority subsystem (lsass.exe) ASR rule (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2-8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-8"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Enabled ASR rule to block LSASS credential theft"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-8: $_"
}
}
