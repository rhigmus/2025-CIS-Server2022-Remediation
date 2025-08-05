function Invoke-Control2312 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.1.2: Status of the name of the Built-in Guest account"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.1.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.1.2: Rename Guest account"
        try {
            Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"  # or another name per your policy
            $cmdOutput = "Renamed built-in Guest account to 'DisabledGuest'."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.1.2: $_"
}
}
