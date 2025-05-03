function Invoke-Control23131 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 23131: Status of the Limit Dump Collection setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 23131"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 23131: Limit Dump Collection"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableDumpCollection" -Value 1 -Type DWord
            $cmdOutput = "Limited dump collection to reduce sensitive data exposure"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 23131: $_"
}
