function Invoke-Control23113 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.11.3: Status of the Network security: Allow PKU2U authentication requests to this computer to use online identities setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.11.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.11.3: PKU2U authentication requests setting"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "AllowOnlineID" -Value 0 -Type DWord
            $cmdOutput = "Disabled PKU2U authentication using online identities"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.11.3: $_"
}
}
