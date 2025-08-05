function Invoke-Control1841 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.4.1: Status of the Apply UAC restrictions to local accounts on network logons settings"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.4.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.4.1: Apply UAC restrictions on network logons"
        try {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Enforced UAC restrictions on local accounts for remote access (LocalAccountTokenFilterPolicy = 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.4.1: $_"
}
}
