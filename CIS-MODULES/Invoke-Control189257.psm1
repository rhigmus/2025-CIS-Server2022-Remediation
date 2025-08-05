function Invoke-Control189257 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.25.7: Status of post-authentication actions (PostAuthenticationResetDelay) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.25.7"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.25.7: PostAuthenticationResetDelay"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PostAuthenticationResetDelay" -PropertyType DWord -Value 30 -Force | Out-Null
            $cmdOutput = "Set PostAuthenticationResetDelay to 30 seconds."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.25.7: $_"
}
}
