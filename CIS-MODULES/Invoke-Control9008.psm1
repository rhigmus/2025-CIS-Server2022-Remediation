function Invoke-Control9008 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9008: Status of the Do not display network selection UI setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9008"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9008"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled network selection UI on logon screen."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9008: $_"
}
