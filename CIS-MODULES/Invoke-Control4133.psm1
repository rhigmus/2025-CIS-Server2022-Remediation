function Invoke-Control4133 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4133: Status of the Require secure RPC communication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4133"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4133"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ForceSecureRpcAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled secure RPC communication."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4133: $_"
}
