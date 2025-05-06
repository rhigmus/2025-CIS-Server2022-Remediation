function Invoke-Control25361 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25361: Status of the Protocols to allow for incoming RPC connections setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25361"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25361"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set RPC RestrictRemoteClients to allow authenticated RPC traffic only."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25361: $_"
}
}
