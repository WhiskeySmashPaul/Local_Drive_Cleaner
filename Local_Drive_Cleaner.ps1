#region  Paramater Bindings

[CmdletBinding()]
    param (
        [Alias("ComputerNames")]
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$CleanCCMCache = $false,

        [Parameter(Mandatory=$false)]
        [int]$ProfileAge = 60
        )

#endregion

#region Variables

$AppName = "Clean-C_Drive"

#endregion

#region Logging

#region Logging Option Variables

$LogPath = "C:\Windows\Logs"
$LogName = "$AppName.log"	
$Log     = Join-Path $LogPath $LogName

#endregion Logging Option Variables

Start-Transcript -Path $Log

#endregion Logging

#region Elevated permissions check

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

#endregion

#region Clean files Working Script

$ScriptBlock = 
{ #Script Start

    param($ProfileAge,$CleanCCMCache)

    #region Calculate Initial Disk Space
    
    write-output "Calculating current disk usage on C:\..."
    $FreespaceBefore = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | Select Freespace)
    write-output ("Disk C:\ has [{0:N2}" -f ($FreespaceBefore.Freespace/1GB) + "] Gb available.")

    #endregion Calculate Initial Disk Space

    #region Clear SCCM Cache if present
    
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

    #endregion Clear SCCM Cache

    #region DISM

    write-output "Starting DISM Cleanup (might take a while)..."
    if ([Environment]::OSVersion.Version -lt (new-object 'Version' 6,2))
    { 
        iex "Dism.exe /online /Cleanup-Image /SpSuperseded"
    }
    else
    { 
        iex "Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase"
    }

    #endregion DISM

    #region VSS Cleanup
        
    write-output "Starting System Restore Points Cleanup..."
    iex "vssadmin.exe Delete Shadows /ALL /Quiet"

    #endregion VSS Cleanup

    #region Profile Cleanup
        
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

    #endregion Profile Cleanup

    #region Windows Updates

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

    #endregion Windows Updates

    #region Windows Temp

    # Cleanup Windows Temp folder:
    write-output "Starting Windows Temp folder Cleanup..."
    Remove-Item "$env:SystemRoot\TEMP\*" -Recurse -Force -ea silentlycontinue

    #endregion Windows Temp

    #region Clear IIS Logs

    #region IIS Logs Variables

    $logPath = "C:\inetpub\logs\LogFiles" 
    $maxDaystoKeep = -5
    $cleanupRecordPath = "C:\Log_Cleanup.log" 
    $itemsToDelete = dir $logPath -Recurse -File *.log | Where LastWriteTime -lt ((get-date).AddDays($maxDaystoKeep))
    
    #endregion IIS Logs Variables
    
    write-output "Starting IIS Logs folder Cleanup..." 

    If ($itemsToDelete.Count -gt 0)
    { 
        ForEach ($item in $itemsToDelete)
        { 
            "$($item.FullName) is older than $((get-date).AddDays($maxDaystoKeep)) and will be deleted."
            Remove-Item $item.FullName -Verbose 
        } 
    } 
    Else
    { 
        "No items to be deleted today $($(Get-Date).DateTime)."
    }    

    Write-Output "Cleanup of log files older than $((get-date).AddDays($maxDaystoKeep)) completed." 


    #endregion Clear IIS Logs

    #region Windows Disk Cleanup
    
        #region Set Disk Cleanup Parameters

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

    #endregion Set Disk Cleanup Parameters

        #region Run Disk Cleanup

            # run it:
            write-output "Starting Cleanmgr with full set of checkmarks (might take a while)..."
            $Process = (Start-Process -FilePath "$env:systemroot\system32\cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -PassThru)
            write-output "Process ended with exitcode [$($Process.ExitCode)]." 
    
        #endregion Run Disk Cleanup        

        #region Space saved from Disk Cleanup

            write-output "Calculating disk usage on C:\..."
            $FreespaceAfter = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | Select Freespace)
            write-output ("Disk C:\ now has [{0:N2}" -f ($FreeSpaceAfter.freespace/1GB) + "] Gb available.")
            write-output ("[{0:N2}" -f (($FreespaceAfter.freespace-$FreespaceBefore.freespace)/1GB) + "] Gb has been liberated on C:\.")
            
        #endregion Space saved from Disk Cleanup    

    #endregion Windows Disk Cleanup

} #Script End

#endregion Clean files Working Script
    
#region Call Script to run 

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

#endregion Call Script

#region Stop Logging

Stop-Transcript

#endregion
