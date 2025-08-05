function Invoke-Control181042611 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.10.42.6.1.1: Status of Attack Surface Reduction group policy"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.10.42.6.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.10.42.6.1.1: Enable ASR group policy enforcement"
        try {
            Set-MpPreference -EnableControlledFolderAccess Enabled
            $cmdOutput = "Enabled Attack Surface Reduction policies via Controlled Folder Access."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.10.42.6.1.1: $_"
}
}
