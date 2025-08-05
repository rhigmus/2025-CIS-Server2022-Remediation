function Invoke-Control181042612-5 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.2-5: Status of Block JavaScript or VBScript from launching downloaded executable content ASR rule (D3E037E1-3EB8-44C8-A917-57927947596D)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.2-5: Status of Block JavaScript or VBScript from launching downloaded executable content ASR rule (D3E037E1-3EB8-44C8-A917-57927947596D)"
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "D3E037E1-3EB8-44C8-A917-57927947596D" -AttackSurfaceReductionRules_Actions Enabled
            $cmdOutput = "Executed remediation step for Control ID 18.10.42.6.1.2-5"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.2-5: $_"
}
}
