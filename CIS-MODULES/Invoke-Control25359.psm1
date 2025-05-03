function Invoke-Control25359 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25359: Status of the Authentication protocol to use for incoming RPC connections setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25359"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25359: Authentication protocol for incoming RPC"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "ForceAuthnLevel" -PropertyType DWord -Value 5 -Force | Out-Null
            $cmdOutput = "Set authentication protocol level to 'PktPrivacy' (5) for incoming RPC connections."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25359: $_"
}
