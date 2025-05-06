function Invoke-Control1513 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1513: Status of the RPC Endpoint Mapper Client Authentication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1513"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1513"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord
            $cmdOutput = "Enabled RPC Endpoint Mapper Client Authentication"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1513: $_"
}
}
