function Invoke-Control189258 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.25.8: Status of Post-authentication actions (PostAuthenticationActions) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.25.8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.25.8: PostAuthenticationActions"
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "PostAuthenticationActions" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set PostAuthenticationActions to 1 to enable lock on reset actions."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.25.8: $_"
}
}
