function Invoke-Control2393 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.9.3: Status of the Microsoft network server: Digitally Sign Communications (if Client agrees) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.9.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.9.3: Digitally sign communications (if client agrees)"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set EnableSecuritySignature to 1 (sign if client agrees)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.9.3: $_"
}
}
