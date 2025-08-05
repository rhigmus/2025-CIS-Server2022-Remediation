function Invoke-Control1858 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.5.8: Status of the MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.5.8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.5.8: Safe DLL search mode"
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord
            $cmdOutput = "Enabled Safe DLL search mode (MSS setting)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.5.8: $_"
}
}
