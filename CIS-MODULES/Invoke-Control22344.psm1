function Invoke-Control22344 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 22344: Status of the DoH Policy setting."
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 22344"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 22344"
        try {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "DoHPolicy" -Value 0 -Type DWord
            $cmdOutput = "Disabled DNS over HTTPS (DoH) via Group Policy"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 22344: $_"
}
}
