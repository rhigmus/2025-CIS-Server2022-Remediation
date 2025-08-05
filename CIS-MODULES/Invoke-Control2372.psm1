function Invoke-Control2372 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.7.2: Status of the Interactive Logon: Do Not Display Last User Name setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.7.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.7.2: Do Not Display Last User Name"
        try {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set DontDisplayLastUserName to 1 (do not display last signed-in user)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.7.2: $_"
}
}
