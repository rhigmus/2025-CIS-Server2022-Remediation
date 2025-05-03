function Invoke-Control11281 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11281: Status of the SMB v1 protocol for LanManServer services on Windows"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11281"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11281: Status of the SMB v1 protocol for LanManServer services on Windows"
        try {
            # Disable SMBv1
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    
            # Also disable the SMB 1.0 feature (if installed)
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    
            $cmdOutput = "Disabled SMBv1 protocol for LanManServer and removed feature if present."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11281: $_"
}
