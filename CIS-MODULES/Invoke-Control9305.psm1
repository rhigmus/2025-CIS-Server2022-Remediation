function Invoke-Control9305 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9305: Status of the Notify antivirus programs when opening attachments configuration [For Windows user]"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9305"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9305: Status of the Notify antivirus programs when opening attachments configuration [For Windows user]"
        try {
            New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 3 -Force | Out-Null
            $cmdOutput = "Enabled attachment scan notification to antivirus (ScanWithAntiVirus set to 3)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9305: $_"
}
