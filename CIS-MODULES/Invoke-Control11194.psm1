function Invoke-Control11194 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 11194: Status of the Block user from showing account details on sign-in setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 11194"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 11194: Block showing account details on sign-in"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Blocked display of account details on sign-in screen."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 11194: $_"
}
