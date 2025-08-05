function Invoke-Control1810563112 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.56.3.11.2: Status of the Do not use temporary folders per session Group Policy setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.56.3.11.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.56.3.11.2: Status of the Do not use temporary folders per session Group Policy setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UseTempFolders" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Executed remediation step for Control ID 18.10.56.3.11.2"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.56.3.11.2: $_"
}
}
