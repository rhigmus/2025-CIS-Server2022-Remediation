function Invoke-Control181056392 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.56.3.9.2: Status of the Require secure RPC communication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.56.3.9.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.56.3.9.2"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ForceSecureRpcAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled secure RPC communication."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.56.3.9.2: $_"
}
}
