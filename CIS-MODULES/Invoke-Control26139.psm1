function Invoke-Control26139 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26139: Status of Post-authentication actions (PostAuthenticationActions) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26139"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26139: PostAuthenticationActions"
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "PostAuthenticationActions" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set PostAuthenticationActions to 1 to enable lock on reset actions."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26139: $_"
}
