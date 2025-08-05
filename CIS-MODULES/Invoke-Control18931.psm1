function Invoke-Control18931 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.3.1: Status of the Include command line in process creation events setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.3.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.3.1: Status of the Include command line in process creation events setting"
        try {
            # Enable command line logging in process creation events
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Enabled inclusion of command line in process creation events."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.3.1: $_"
}
}
