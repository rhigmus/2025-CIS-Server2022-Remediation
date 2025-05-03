function Invoke-Control10592 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10592: Status of the Hardened UNC Paths setting for Netlogon"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10592"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10592: Status of the Hardened UNC Paths setting for Netlogon"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 10592"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10592: $_"
}
