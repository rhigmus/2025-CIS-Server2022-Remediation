function Invoke-Control26138 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 26138: Status of password (PasswordComplexity) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 26138"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 26138: Status of password (PasswordComplexity) setting"
        try {
            # Enable Password Complexity requirement
            secedit /export /cfg C:\Windows\Temp\secedit_export.inf
            (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "(PasswordComplexity\s*=).*", "`$1 1" | Set-Content C:\Windows\Temp\secedit_update.inf
            secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas SECURITYPOLICY
            Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force
    
            $cmdOutput = "Set PasswordComplexity to enabled (value 1) via secedit."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 26138: $_"
}
}
