function Invoke-Control1810411 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.41.1: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.41.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.41.1: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 18.10.41.1"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.41.1: $_"
}
}
