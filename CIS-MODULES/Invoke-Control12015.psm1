function Invoke-Control12015 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 12015: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 12015"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 12015: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 12015"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 12015: $_"
}
}
