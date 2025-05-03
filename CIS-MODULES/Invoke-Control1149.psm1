function Invoke-Control1149 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1149: Status of the Microsoft network client: Digitally sign communications (always) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1149"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1149: Status of the Microsoft network client: Digitally sign communications (always) setting"
        try {
            # Set Microsoft network client to always digitally sign communications
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set RequireSecuritySignature to 1 under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1149: $_"
}
