function Invoke-Control23103 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.10.3: Status of the Network Access: Do not allow Anonymous Enumeration of SAM Accounts and Shares setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.10.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.10.3: Disable anonymous SAM/Shares enumeration"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set RestrictAnonymous = 1 (disallow anonymous enumeration)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.10.3: $_"
}
}
