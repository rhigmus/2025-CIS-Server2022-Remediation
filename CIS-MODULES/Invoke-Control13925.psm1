function Invoke-Control13925 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 13925: Status of Block Win32 API calls from Office macro ASR rule (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 13925"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 13925: Status of Block Win32 API calls from Office macro ASR rule"
        try {
            # Enable ASR rule to block Win32 API calls from Office macros
            Add-MpPreference -AttackSurfaceReductionRules_Ids "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -AttackSurfaceReductionRules_Actions Enabled
    
            $cmdOutput = "Enabled ASR rule: Block Win32 API calls from Office macro (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 13925: $_"
}
