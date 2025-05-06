function Invoke-Control2200 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2200: Current list of Groups and User Accounts granted the Deny logon through terminal (Remote Desktop) service right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2200"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2200"
        try {
            ntrights -u "Guests" +r SeDenyRemoteInteractiveLogonRight
            $cmdOutput = "Applied Deny logon through Remote Desktop Services to Guests"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2200: $_"
}
}
