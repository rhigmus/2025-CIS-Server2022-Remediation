function Invoke-Control2607 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2607: Status of the Prohibit use of Internet Connection Sharing on your DNS domain network setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2607"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2607"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled Internet Connection Sharing UI on DNS domain network."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2607: $_"
}
}
