function Invoke-Control189361 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.36.1: Status of the RPC Endpoint Mapper Client Authentication setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.36.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.36.1"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord
            $cmdOutput = "Enabled RPC Endpoint Mapper Client Authentication"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.36.1: $_"
}
}
