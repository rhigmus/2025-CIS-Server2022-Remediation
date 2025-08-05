function Invoke-Control1810142 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.14.2: Status of Enumerate administrator accounts on elevation setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.14.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.14.2: Disable enumerating admin accounts on elevation"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled enumeration of admin accounts on elevation prompt."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.14.2: $_"
}
}
