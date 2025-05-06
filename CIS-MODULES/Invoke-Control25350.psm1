function Invoke-Control25350 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25350: Status of the Allow Custom SSPs and APs to be loaded into LSASS setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25350"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25350: Disable loading of custom SSPs and APs into LSASS"
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -PropertyType MultiString -Value "kerberos","msv1_0","wdigest","tspkg","pku2u","schannel" -Force | Out-Null
            $cmdOutput = "Ensured only default SSPs/APs are configured under Security Packages."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25350: $_"
}
}
