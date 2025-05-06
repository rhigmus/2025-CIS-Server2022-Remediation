function Invoke-Control11034 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11034: Configure Prevent Device Metadata Retrieval from Internet Windows Group Policy"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11034"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11034: Configure Prevent Device Metadata Retrieval from Internet Windows Group Policy"
        try {
            # Disable metadata retrieval from the Internet
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Set PreventDeviceMetadataFromNetwork to 1 (disables Internet retrieval of metadata)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11034: $_"
}
}
