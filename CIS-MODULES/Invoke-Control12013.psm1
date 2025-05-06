function Invoke-Control12013 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 12013: Status of the Remote host allows delegation of non-exportable credentials (AllowProtectedCreds) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 12013"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 12013: Status of the Remote host allows delegation of non-exportable credentials (AllowProtectedCreds) setting"
        try {
            # Allow delegation of non-exportable credentials (Protected Users Group protection)
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "AllowProtectedCreds" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Enabled AllowProtectedCreds (set to 1) under HKLM:\System\CurrentControlSet\Control\Lsa"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 12013: $_"
}
}
