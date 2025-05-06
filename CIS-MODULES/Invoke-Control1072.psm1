function Invoke-Control1072 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1072: Status of the Minimum Password Age setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1072"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1072"
        try {
            net accounts /minpwage:1
            $cmdOutput = "Set minimum password age to 1 day"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1072: $_"
}
}
