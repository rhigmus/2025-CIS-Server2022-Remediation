function Invoke-Control2211 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.2.11: Current list of Groups and User Accounts granted the Back up files and directories right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.2.11"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.2.11: Back up files and directories right"
        try {
            ntrights -u "Administrators" +r SeBackupPrivilege
            $cmdOutput = "Granted 'Back up files and directories' right to Administrators (SeBackupPrivilege)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.2.11: $_"
}
}
