function Invoke-Control10081 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10081: Status of the Require domain users to elevate when setting a networks location setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10081"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10081: Status of the Require domain users to elevate when setting a networks location setting"
        try {
            # Require elevation to change network location (domain-joined systems)
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Set NC_StdDomainUserSetLocation to 1 (requires elevation for network location changes)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10081: $_"
}
