function Invoke-Control3899 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3899: Status of the Solicited Remote Assistance policy setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3899"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3899: Solicited Remote Assistance policy"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled Solicited Remote Assistance (fAllowToGetHelp set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3899: $_"
}
