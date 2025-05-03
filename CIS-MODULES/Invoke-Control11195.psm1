function Invoke-Control11195 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11195: Status of the NetBIOS node type setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11195"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11195: Status of the NetBIOS node type setting"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
            $cmdOutput = "Set NetBIOS NodeType to 2 (P-node only)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11195: $_"
}
