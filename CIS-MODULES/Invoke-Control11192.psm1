function Invoke-Control11192 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11192: Status of the Turn off multicast name resolution setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11192"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11192: Turn off multicast name resolution"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled multicast name resolution (EnableMulticast set to 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11192: $_"
}
}
