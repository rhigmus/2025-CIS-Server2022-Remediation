function Invoke-Control25360 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25360: Status of the Use authentication for outgoing RPC over named pipes connections setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25360"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25360: Status of the Use authentication for outgoing RPC over named pipes connections setting"
        try {
            # Require authentication for outbound RPC over named pipes
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
    
            $cmdOutput = "Enabled authentication for outbound RPC over named pipes by setting HardenedPaths for \\*"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25360: $_"
}
