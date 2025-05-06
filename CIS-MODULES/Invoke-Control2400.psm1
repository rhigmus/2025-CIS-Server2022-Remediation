function Invoke-Control2400 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2400: Current list of Groups and User Accounts granted the Shut down the system (SeShutdownPrivilege) right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2400"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2400: Shut down the system"
        try {
            ntrights -u "Users" +r SeShutdownPrivilege
            $cmdOutput = "Granted 'Shut down the system' right to Users (SeShutdownPrivilege). Modify account/group as needed."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2400: $_"
}
}
