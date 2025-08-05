function Invoke-Control18109242 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.92.4.2: Status of the Select when Feature Updates are received - DeferFeatureUpdatesPeriodInDays setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.92.4.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.92.4.2: Feature Updates Deferment"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180 -Type DWord
            $cmdOutput = "Configured Windows to defer feature updates for 30 days"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.92.4.2: $_"
}
}
