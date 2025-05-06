function Invoke-Control10593 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10593: Status of the Hardened UNC Paths setting for Sysvol"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10593"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10593: Status of the Hardened UNC Paths setting for Sysvol"
        try {
            # Enforce hardened UNC paths for SYSVOL and NETLOGON
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
    
            $cmdOutput = "Set Hardened UNC Paths for SYSVOL and NETLOGON with mutual authentication and integrity required."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10593: $_"
}
}
