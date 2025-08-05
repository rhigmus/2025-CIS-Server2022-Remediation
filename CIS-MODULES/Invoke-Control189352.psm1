function Invoke-Control189352 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.35.2: Status of the Solicited Remote Assistance policy setting (Terminal Services)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.35.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.35.2: Solicited Remote Assistance policy"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled Solicited Remote Assistance (fAllowToGetHelp set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.35.2: $_"
}
}
