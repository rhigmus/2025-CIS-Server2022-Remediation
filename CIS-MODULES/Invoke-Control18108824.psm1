function Invoke-Control18108824 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.88.2.4: Status of the Disallow WinRM from storing RunAs credentials setting (WinRM service)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.88.2.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.88.2.4"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1 -Type DWord
            $cmdOutput = "Disabled storing of RunAs credentials by WinRM (DisableRunAs = 1)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.88.2.4: $_"
}
}
