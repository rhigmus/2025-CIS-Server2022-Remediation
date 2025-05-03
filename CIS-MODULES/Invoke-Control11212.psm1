function Invoke-Control11212 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11212: Status of the Select when Feature Updates are received - DeferFeatureUpdatesPeriodInDays setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11212"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11212: Feature Updates Deferment"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 30 -Type DWord
            $cmdOutput = "Configured Windows to defer feature updates for 30 days"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11212: $_"
}
