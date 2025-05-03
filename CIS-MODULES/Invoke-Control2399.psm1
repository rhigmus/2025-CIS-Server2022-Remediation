function Invoke-Control2399 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2399: Current list of Groups and User Accounts granted the Restore files and directories (SeRestorePrivilege) right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2399"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2399: Restore files and directories right"
        try {
            ntrights -u "Administrators" +r SeRestorePrivilege
            $cmdOutput = "Granted 'Restore files and directories' right to Administrators (SeRestorePrivilege)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2399: $_"
}
