function Invoke-Control189194 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.19.4: Status of the Configure security policy processing: Do not apply during periodic background processing setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.19.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.19.4: Do not apply during periodic background processing"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\0" -Name "NoBackgroundPolicy" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Set NoBackgroundPolicy to 0 to allow policy processing during background refresh."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.19.4: $_"
}
}
