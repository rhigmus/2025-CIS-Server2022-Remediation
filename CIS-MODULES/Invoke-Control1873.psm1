function Invoke-Control1873 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.7.3: Status of the Configure RPC connection settings: Protocol to use for outgoing RPC connections setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.7.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.7.3: Configure RPC connection settings"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ForceRpcSecurity" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set ForceRpcSecurity to 1 to enforce secure protocol for outgoing RPC connections."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.7.3: $_"
}
}
