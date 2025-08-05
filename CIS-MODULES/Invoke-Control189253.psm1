function Invoke-Control189253 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.25.3: Status of enable password encryption setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.25.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.25.3: Enable password encryption"
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
            $cmdOutput = "Enforced encrypted password use for network authentication"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.25.3: $_"
}
}
