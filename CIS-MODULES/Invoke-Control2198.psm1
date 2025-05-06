function Invoke-Control2198 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2198: Current list of Groups and User Accounts granted the Deny logon as a service right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2198"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2198"
        try {
            ntrights -u "Guests" -m \\localhost +r SeDenyServiceLogonRight
            $cmdOutput = "Applied 'Deny logon as a service' to Guests group."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2198: $_"
}
}
