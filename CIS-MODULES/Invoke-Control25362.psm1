function Invoke-Control25362 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25362: Status of the Configure RPC over TCP port setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25362"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25362: Status of the Configure RPC over TCP port setting"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "Ports" -Value "5000-5100" -Type MultiString
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "PortsInternetAvailable" -Value "Y"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "UseInternetPorts" -Value 1 -Type DWord
            $cmdOutput = "Configured RPC to use ports 5000-5100 over TCP"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25362: $_"
}
