function Invoke-Control23132 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23132: Status of the Limit Diagnostic Log Collection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23132"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23132"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord
            $cmdOutput = "Set LimitDiagnosticLogCollection to 1 (Enabled)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23132: $_"
}
