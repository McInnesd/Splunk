<#
    .SYNOPSIS
        Installs or upgrades the Splunk Universal Forwarder on a host.
    .DESCRIPTION
        - Install splunk forwarder
        - Remove system/local files
        - Install base config app(s)

        - Default detection of system local files (deletion)
            * deploymentclient.conf
            * outputs.conf

        - Default installation of base config app
            * org_all_deploymentclient

        - Use param LocalConfToDelete to pass and array of conf files
          to delete from system/local

        - Use param SplunkAppsToInstall to pass an array of splunk
          apps to install from the directory where the script is run

        - The Splunk Forwarder MSI package must be located in the same
          directory as the script.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$LocalConfToDelete = ("deploymentclient.conf", "outputs.conf"),

    [Parameter(Mandatory = $false)]
    [string[]]$SplunkAppsToInstall = ("org_all_deploymentclient")
)

Function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $false)]
        [String]$LogFilePath = (Join-Path -Path $SplunkHomePath -ChildPath "\var\log\splunk\splunk_migration.log"),

        [Parameter(Mandatory = $false)]
        [String]$LogLevel = "INFO"
    )

    $enus = [System.Globalization.CultureInfo]::new("en-US")
    $DateTimeNow = (get-date).tostring("yyyy.MM.dd hh:mm:ss.ffffff tt K", $enus)
    $Message = "$DateTimeNow [$LogLevel] $Message"
    Add-Content -Path $LogFilePath -Value $Message
}

$SplunkVersionRegex = "splunkforwarder-([^-]+)-[a-z0-9]+-windows-x\d{2}\.msi"

$SplunkForwarderMSI = @(Get-ChildItem -Path $PSScriptRoot -Filter "*.msi")

if ($SplunkForwarderMSI.Count -ne 1) {
    throw "Expected exactly one MSI package in $PSScriptRoot, found $($SplunkForwarderMSI.Count)"
}
$SplunkForwarderMSI = $SplunkForwarderMSI[0].FullName

if (!(Test-Path -Path $SplunkForwarderMSI)){
    throw "Splunk Forwarder MSI package not found"
}

if ($SplunkForwarderMSI.Split("\")[-1] -match $SplunkVersionRegex) {
    [version]$NewSplunkVersion = $Matches[1]
} else {
    throw "Unable to find new splunk version from filename $($SplunkForwarderMSI.Split("\")[-1])"
}


try {
    $SplunkServiceBinPath           = (Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'").PathName
    $SplunkdPath                    = ($SplunkServiceBinPath -replace '"','') -replace " service$", ""
    $SplunkHomePath                 = $SplunkdPath.Replace("\bin\splunkd.exe","")
    [version]$CurrentSplunkVersion  = (Get-ItemProperty $SplunkdPath).VersionInfo.FileVersion

    if ($CurrentSplunkVersion -ge $NewSplunkVersion) {
        Write-Log -LogLevel "INFO" -Message "Splunk Forwarder is already at version $CurrentSplunkVersion or newer. Skipping upgrade."
        return
    }

    Write-Log -LogLevel "INFO" -Message "Upgrading Splunk Forwarder from $CurrentSplunkVersion to $NewSplunkVersion"
} catch {
    Write-Log -LogLevel "INFO" -LogFilePath "$PSScriptRoot\splunk_install.log" -Message "Splunk Forwarder not found. This is a clean install"
    $proc = Start-Process -FilePath "C:\Windows\system32\msiexec.exe" -Wait -PassThru -NoNewWindow -ArgumentList "/i `"$SplunkForwarderMSI`" AGREETOLICENSE=Yes LAUNCHSPLUNK=0 /q"
    if ($proc.ExitCode -ne 0) {
        throw "MSI install failed with exit code $($proc.ExitCode)"
    }
    $SplunkHomePath = "C:\Program Files\SplunkUniversalForwarder"
    $CleanInstall = $true
}

$SplunkAppsPath        = Join-Path -Path $SplunkHomePath -ChildPath "\etc\apps"
$SplunkSystemLocalPath = Join-Path -Path $SplunkHomePath -ChildPath "\etc\system\local"

foreach ($ConfFile in $LocalConfToDelete){
    $ConfFilePath = Join-Path -Path $SplunkSystemLocalPath -ChildPath $ConfFile
    if (Test-Path -Path $ConfFilePath) {
        Write-Log -LogLevel "INFO" -Message "Found $ConfFile in system local filepath=$ConfFilePath"
        
        try {
            Write-Log -LogLevel "INFO" -Message "Removing $ConfFile from system local filepath=$ConfFilePath"
            Remove-Item -Path $ConfFilePath
        } catch {
            Write-Log -LogLevel "ERROR" -Message "Unable to remove $ConfFilePath - $_"
        }
    }
}

if (!$CleanInstall) {
    Write-Log -LogLevel "INFO" -Message "Update process start upgrade splunk forwarder"
    $proc = Start-Process -FilePath "C:\Windows\system32\msiexec.exe" -Wait -PassThru -NoNewWindow -ArgumentList "/i `"$SplunkForwarderMSI`" AGREETOLICENSE=Yes LAUNCHSPLUNK=0 /q"
    if ($proc.ExitCode -ne 0) {
        throw "MSI install failed with exit code $($proc.ExitCode)"
    }
}

foreach ($SplunkApp in $SplunkAppsToInstall){
    $AppPath = Join-Path -Path $PSScriptRoot -ChildPath $SplunkApp
    if (Test-Path -Path (Join-Path -Path $AppPath -ChildPath "local\app.conf")) {
        Write-Log -LogLevel "INFO" -Message "Found Splunk app to install $AppPath"
        Copy-Item -Recurse -Force -Path $AppPath -Destination $SplunkAppsPath
    }
}

if (!((Get-Service -Name SplunkForwarder).Status -eq "Running")) {
    Start-Service -Name SplunkForwarder
}
Write-Log -LogLevel "INFO" -Message "Splunk forwarder upgrade complete. version=$NewSplunkVersion"
