function Invoke-Control2223 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.2.23: Current list of Groups and User Accounts granted the Deny logon as a batch job right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.2.23"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.2.23: Deny logon as a batch job"
        try {
            ntrights -u "Guests" +r SeDenyBatchLogonRight
            $cmdOutput = "Assigned 'Deny logon as a batch job' right to Guests (SeDenyBatchLogonRight)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.2.23: $_"
}
}
