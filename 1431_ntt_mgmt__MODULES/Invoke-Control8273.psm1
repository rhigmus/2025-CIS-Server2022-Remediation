function Invoke-Control8273 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8273: Status of the Turn off Data Execution Prevention for Explorer setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8273"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8273: Disable DEP for Explorer"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Ensured DEP is enabled for Explorer (NoDataExecutionPrevention set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8273: $_"
}
