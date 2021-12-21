<#
.SYNOPSIS
    Automates the tedious task of disk cleanups.

.DESCRIPTION
    The script relies entirely on tools and mechanisms that are present in Windows by default. So no worries about it breaking stuff (as can sometimes happen with 3rd-party tools).

    Important note: To clean up remotely, WinRM needs to be enabled on the target.

.PARAMETER ComputerName
    Hostname or FQDN of a remote computer. To enter multiple computers, separate them by a comma.
    If this value is not present or left blank, the script will clean up the local computer.

.PARAMETER ProfileAge
    Specifies the maximum age (in days) of locally cached user profiles. Profiles older than this value will be deleted.
    If this value is not specified it will default to 7 days.

.EXAMPLE   
   To clean up the local computer, start an elevated Powershell prompt, cd to the folder containing the script and enter:
        
        .\Clean-C_Drive.ps1

.EXAMPLE
    To clean up a remote computer called "COMPUTER1":
        
        .\Clean-C_Drive.ps1 -ComputerName COMPUTER1

.EXAMPLE
    To cleanup everything, including profiles that haven't been used for more than 30 days, on multiple remote computers:
        
        .\Clean-C_Drive.ps1 -Computername COMPUTER1,COMPUTER2,COMPUTER3 -ProfileAge 30

.NOTES
    
    19-11-2018:
        - Cleaned up code and help text
        - Replaced custom logging and verbose output with Transcript logging.

    01-06-2016:
        - Improved windows update service handling to prevent a script hang on detecting stopped state.

    02-03-2016:
        - Added automated Disk Cleanup (Cleanmgr.exe) 
        - Added parameter for ProfileAge. Profiles older than x number of days will be deleted. Default value is 7.
        - Updated Help.

    26-02-2016:        
        - Added User Profile Cleanup.

    09-02-2016:
        - Added System Restore Point cleanup.

    22-12-2015
        - Initial working script.

#>

[CmdletBinding()]
    param (
        [Alias("ComputerNames")]
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$CleanCCMCache = $false,

        [Parameter(Mandatory=$false)]
        [int]$ProfileAge = 150
        )

$AppName = "Clean-C_Drive"

# Logging:
$LogPath = "C:\Windows\Logs"
$LogName = "$AppName.log"	
$Log     = Join-Path $LogPath $LogName

Start-Transcript -Path $Log

# Detect Elevation:
$CurrentUser=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal=New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin=$UserPrincipal.IsInRole($AdminRole)

if ($IsAdmin)
{
   write-output "Script is running elevated."
}
else 
{
   throw "Script is not running elevated, which is required. Restart the script from an elevated prompt."
}

if (-not($ComputerName))
{ 
    write-host "No target(s) specified, defaulting to local machine."
    $ComputerNames = $env:ComputerName 
}

# The business end...:
$ScriptBlock = 
{
    param($ProfileAge,$CleanCCMCache)
    
    write-output "Calculating current disk usage on C:\..."
    $FreespaceBefore = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | Select Freespace)
    write-output ("Disk C:\ has [{0:N2}" -f ($FreespaceBefore.Freespace/1GB) + "] Gb available.")
    
    if ($CleanCCMCache)
    {
        try
        {
            if (gwmi -namespace "root\ccm" -class "SMS_Client" -ea Stop)
            {
        
                write-output "Starting CCM cache Cleanup..."
                $UIResourceMgr = New-Object -ComObject UIResource.UIResourceMgr 
                $Cache = $UIResourceMgr.GetCacheInfo()
                $CacheElements = $Cache.GetCacheElements()

                foreach ($Element in $CacheElements)
                {
                    write-output "Deleting PackageID [$($Element.ContentID)] in folder [$($Element.Location)]"
                    $Cache.DeleteCacheElement($Element.CacheElementID)
                }
            }
        }
        catch
        {
            if (Test-Path "\\$ComputerName\C$\Windows\ccmcache")
            {
                write-output "No CM agent found in WMI but a cache folder is present. Cache will NOT be cleared!"
            }
            else
            { 
                write-output "No CM agent found in WMI and no cache folder detected. Nothing to see here...moving along..." 
            }
        }
    }

    write-output "Starting DISM Cleanup (might take a while)..."
    if ([Environment]::OSVersion.Version -lt (new-object 'Version' 6,2))
    { 
        iex "Dism.exe /online /Cleanup-Image /SpSuperseded"
    }
    else
    { 
        iex "Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase"
    }
        
    write-output "Starting System Restore Points Cleanup..."
    iex "vssadmin.exe Delete Shadows /ALL /Quiet"
        
    write-output "Starting User Profile Cleanup..."
    write-output "Checking for user profiles that are older than [$ProfileAge] days..."
    gwmi -Class Win32_UserProfile | where {-not $_.Special} | foreach {
        $Profile = $_
        try
        {
            $LastUsed = $Profile.ConvertToDateTime($Profile.LastUseTime)
        }
        Catch
        {
            # if listed in WMI but without any properties (as in; no LastUseTime)...catch the time error:
            write-output "Orphaned record found: [$($Profile.Localpath)] - [$($Profile.SID)]"
            $Profile.Delete()                                
        }
        Finally 
        {
            if ($LastUsed -lt (get-date).AddDays(-$ProfileAge))
            {
                write-output "Deleting: [$($Profile.LocalPath)] - Last used on [$LastUsed]"
                $Profile.Delete() 
            } 
            else 
            {
                write-output "Skipping: [$($Profile.LocalPath)] - Last used on [$LastUsed]"
            }
        }
    }

    # Cleanup WUA:
    write-output "Starting Windows Update Cleanup..."    
    [int]$seconds = 0
    Do 
    {    
        if ($seconds -ge 120){ throw "Timed out after [$seconds] seconds." }
        Stop-Service -Name wuauserv -Force
        write-output "waiting for 'Windows Update' service to stop..." 
        Start-Sleep -Seconds 5
        $seconds = $seconds + 5
 
    } 
    while ((get-service -Name wuauserv).status -ne "Stopped")
        write-output "Deleting [$env:SystemRoot\SoftwareDistribution]..."
        Remove-Item "$env:SystemRoot\SoftwareDistribution" -Recurse -Force -ea SilentlyContinue

    if ((get-service -Name wuauserv).status -ne "Running")
    {
        write-output "Starting 'Windows Update service...'"    
        Start-Service -Name wuauserv
    }

    # Cleanup Windows Temp folder:
    write-output "Starting Windows Temp folder Cleanup..."
    Remove-Item "$env:SystemRoot\TEMP\*" -Recurse -Force -ea silentlycontinue
    
    # Create Cleanmgr profile:
    write-output "Starting Disk Cleanup utility..."
    $ErrorActionPreference = "SilentlyContinue"
    $CleanMgrKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    if (-not (get-itemproperty -path "$CleanMgrKey\Temporary Files" -name StateFlags0001))
    {
        set-itemproperty -path "$CleanMgrKey\Active Setup Temp Folders" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\BranchCache" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Downloaded Program Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Internet Cache Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Memory Dump Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Old ChkDsk Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Previous Installations" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Recycle Bin" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Service Pack Cleanup" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Setup Log Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\System error memory dump files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\System error minidump files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Temporary Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Temporary Setup Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Thumbnail Cache" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Update Cleanup" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Upgrade Discarded Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\User file versions" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Defender" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Error Reporting Archive Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Error Reporting Queue Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Error Reporting System Archive Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Error Reporting System Queue Files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows ESD installation files" -name StateFlags0001 -type DWORD -Value 2
        set-itemproperty -path "$CleanMgrKey\Windows Upgrade Log Files" -name StateFlags0001 -type DWORD -Value 2
    }
    # run it:
    write-output "Starting Cleanmgr with full set of checkmarks (might take a while)..."
    $Process = (Start-Process -FilePath "$env:systemroot\system32\cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -PassThru)
    write-output "Process ended with exitcode [$($Process.ExitCode)]."         

    write-output "Calculating disk usage on C:\..."
    $FreespaceAfter = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | Select Freespace)
    write-output ("Disk C:\ now has [{0:N2}" -f ($FreeSpaceAfter.freespace/1GB) + "] Gb available.")
    write-output ("[{0:N2}" -f (($FreespaceAfter.freespace-$FreespaceBefore.freespace)/1GB) + "] Gb has been liberated on C:\.")    
}

foreach ($ComputerName in $ComputerNames)
{
    try
    {
        # Measure running time.
        $Start = Get-Date   
        write-output "$(Get-Date) - Starting cleanup on [$ComputerName]..." 
        if ($ComputerName -eq $env:ComputerName)
        { 
            Invoke-Command -ArgumentList $ProfileAge,$CleanCCMCache -ScriptBlock $ScriptBlock -ea Stop
        } 
        else 
        { 
            Invoke-Command -ComputerName $ComputerName -ArgumentList $ProfileAge,$CleanCCMCache -ScriptBlock $ScriptBlock -ea Stop 
        }          
    } 
    catch 
    { 
        write-error "Unable to clean [$ComputerName] because [$($_.Exception.Message)]" 
    } 
    Finally 
    {
        $End = Get-Date
        $TimeSpan = New-TimeSpan -Start $Start -End $End    
        "$(Get-Date) - [$ComputerName] cleaned in: {0:hh} hours {0:mm} minutes and {0:ss} seconds." -f $TimeSpan
    } 
}

Stop-Transcript
