function Invoke-Control25340 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25340: Status of the Manage processing of Queue-specific files setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25340"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25340: Status of the Manage processing of Queue-specific files setting"
        try {
            # Disable processing of queue-specific files
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -PropertyType DWord -Value 2 -Force | Out-Null
    
            $cmdOutput = "Disabled processing of Queue-specific files (RegisterSpoolerRemoteRpcEndPoint set to 2)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25340: $_"
}
