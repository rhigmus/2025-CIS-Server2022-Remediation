function Invoke-Control23171 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.17.1: Status of the User Account Control: Admin Approval Mode for the Built-in Administrator account setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.17.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.17.1: Admin Approval Mode for Built-in Administrator"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Enabled Admin Approval Mode for Built-in Administrator (FilterAdministratorToken = 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.17.1: $_"
}
}
