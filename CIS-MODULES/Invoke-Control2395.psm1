function Invoke-Control2395 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.9.5: Status of the Microsoft network server: Server SPN target name validation level setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.9.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.9.5: Server SPN target name validation level"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMBServerNameHardeningLevel" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set SMBServerNameHardeningLevel to 1 to enable SPN target name validation."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.9.5: $_"
}
}
