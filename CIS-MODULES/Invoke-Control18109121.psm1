function Invoke-Control18109121 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.91.2.1: Status of the Prevent users from modifying settings setting for Windows Defender Exploit Protection"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.91.2.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.91.2.1: Prevent users from modifying Exploit Protection settings"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\ExploitGuard\ExploitProtection" -Name "ExploitProtection_Settings" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set ExploitProtection_Settings to 1 to prevent users from modifying Exploit Protection settings."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.91.2.1: $_"
}
}
