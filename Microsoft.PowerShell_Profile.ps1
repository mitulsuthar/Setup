Function Load-AllModules{
Import-module ActiveDirectory
Import-module WebAdministration
Import-module Pscx
Import-module GroupPolicy
Import-module C:\scripts\AddItemToContext\AddItemToContext.psm1
}
Add-PSSNapin TfsBPAPowerShellSnapIn -ErrorAction SilentlyContinue
#Add-PSSnapin SQLServerCmdletSnapin100
#Add-PSSnapin SQLServerProviderSnapin100

Add-PSSnapin "WDeploySnapin3.0"

New-Alias LAME -Value Load-AllModules
##LAME
function Get-AccountExpirationDate([object]$LargeInteger){  
    $type = $LargeInteger.GetType()  
    $highPart = $type.InvokeMember("HighPart","GetProperty",$null,$LargeInteger,$null)  
    $lowPart = $type.InvokeMember("LowPart","GetProperty",$null,$LargeInteger,$null)  
    $bytes = [System.BitConverter]::GetBytes($highPart)  
    $tmp = New-Object System.Byte[] 8  
    [Array]::Copy($bytes,0,$tmp,4,4)  
    $highPart = [System.BitConverter]::ToInt64($tmp,0)  
    $bytes = [System.BitConverter]::GetBytes($lowPart)  
    $lowPart = [System.BitConverter]::ToUInt32($bytes,0)  
    $a = $lowPart + $highPart  
	[datetime]::FromFileTimeUtc($a)	
}

function zoom
{
	start-process "C:\SysInternals\ZoomIt\Zoomit.exe"
}
Function Copy-LastCommand {
 (Get-History)[-1].commandline | clip
}
#checks a list of users in AD group and throws out all people who are not members of that group.
function Check-AdUserInGroup {
    param(
    [parameter(Mandatory=$true)]
    [string]$groupname,
    [parameter()]
    [switch]$ReturnNonMembers,
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [ValidateNotNullorEmpty()]
    [string[]]
    $usernames
    )
    $usernames | Foreach-Object {
     $user = $_;
     $count = 0;
		    (Get-ADUSER $_.ToString() -Properties MemberOf | Select MemberOf).MemberOf.Value.GetEnumerator() |  Foreach-object  {             
                $usergroup = $_.Substring(3,$_.Split(",")[0].length-3).ToLower();
                if ($usergroup -eq $groupname.ToLower()){
                    $count = $count + 1;
                    if($ReturnNonMembers -eq $false){
                        Write-Verbose "$user is in  $usergroup ";
                        return $user;
			        }
                }            
		    }
            if($count -eq 0){
                 if($ReturnNonMembers -eq $true){
                    Write-Verbose "$User is not in $groupname";
                    return $user;
                }
            }
	    }
}
function Search-Help{
param(
    ## The pattern to search for
    [Parameter(Mandatory = $true)]
    $Pattern
) 
Set-StrictMode -Version Latest 
$helpNames = $(Get-Help * | Where-Object { $_.Category -ne "Alias" }) 
## Go through all of the help topics
foreach($helpTopic in $helpNames)
	{
    ## Get their text content, and
		$content = Get-Help -Full $helpTopic.Name | Out-String
		if($content -match $Pattern)
		{
			$helpTopic | Add-Member NoteProperty Match $matches[0].Trim()
			$helpTopic | Select-Object Name,Match
		}
	}
}
function Test-ADUser {
	param(
	[string]$username,
	[string]$password )
	#$cred = Get-Credential #Read credentials
	#$username = $cred.username
	#$password = $cred.GetNetworkCredential().password
	# Get current domain using logged-on user's credentials
	$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
	$domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)
	if ($domain.name -eq $null)	{
		write-host "Authentication failed - please verify your username and password."		
	}
	else
	{
		write-host "Successfully authenticated with domain $domain.name"
	}
}

function pro { & "C:\Program Files (x86)\notepad++\notepad++.exe" $profile}
function n { & "C:\Program Files (x86)\notepad++\notepad++.exe" }
function ne { & "C:\Users\msuthar\AppData\Local\Google\Chrome\Application\chrome.exe" http://blog.cwa.me.uk/,http://www.alvinashcraft.com/}
function vol { & "C:\windows\system32\sndvol.exe" -f}
function so { 
& "C:\Users\msuthar\AppData\Local\Google\Chrome\Application\chrome.exe" http://stackoverflow.com/questions/tagged/powershell,
http://stackoverflow.com/questions/tagged/asp.net?sort=newest`&pagesize=100}
function sleep-computer { rundll32.exe powrprof.dll, SetSuspendState 0,1,0 }
function g { 
param([string]$searchstring)
& "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" https://www.google.com/search?q=$searchstring
}
function goto {
param(
[parameter(Mandatory=$true,ValueFromPipeline=$true)]
[string]$url)
& "C:\Program files (x86)\Google\Chrome\Application\chrome.exe" $url
}
function rmd {
param([string]$computername)
& "C:\windows\system32\mstsc.exe" /v:$computername /fullscreen
}
function Get-ErrorInfo
{ 
param([string]$errorobject)
& "C:\Users\msuthar\AppData\Local\Google\Chrome\Application\chrome.exe"  https://www.google.com/search?q=$errorobject.Exception
}

function RestartComputer
{
param([string]$Computer)
If (Test-Connection -Computer $Computer -count 1 -Quiet) { 
                Try { 
                    Restart-Computer -ComputerName $Computer -Force -ea stop 
                    Do { 
                        Start-Sleep -Seconds 2 
                        Write-Output "Waiting for $Computer to shutdown..." 
                        } 
                    While ((Test-Connection -ComputerName $Computer -Count 1 -Quiet))    
                    Do { 
                        Start-Sleep -Seconds 10 
                        $i++        
                        Write-Output "$Computer down...$($i)" 
                        #5 minute threshold (5*60) 
                        If($i -eq 60) { 
                            Write-Output "$Computer did not come back online from reboot!" 
                            Write-Output $False 
                            } 
                        } 
                    While (-NOT(Test-Connection -ComputerName $Computer -Count 1 -Quiet)) 
                    Write-Output "$Computer is back up and waiting for 120 seconds." 
                    Start-Sleep -Seconds 120                                        
                    Write-Output $True 
                } Catch { 
                    Write-Warning "$($Error[0])" 
                    Write-Output $False 
                } 
} Else { 
  Write-Output $False 
} 
}
function test-regex {
param(
[string]$inputString,
[string]$regex
)
$match = [System.Text.RegularExpressions.Regex]::Match($inputString,$regex)
Write-Host $match.Value -foreground "Yellow" 
}
function Get-ComputerNameByIP {
    param(
        $IPAddress = $null
    )
    BEGIN {
    }
    PROCESS {
        if ($IPAddress -and $_) {
            throw 'Please use either pipeline or input parameter'
            break
        } elseif ($IPAddress) {
            ([System.Net.Dns]::GetHostbyAddress($IPAddress)).HostName
        } elseif ($_) {
            [System.Net.Dns]::GetHostbyAddress($_).HostName
        } else {
            $IPAddress = Read-Host "Please supply the IP Address"
            [System.Net.Dns]::GetHostbyAddress($IPAddress).HostName
        }
    }
    END {
    }
}
function Add-PathToEnv{
	param(
	[string]$path
	)
	$env:Path += ";$path"
}

function Open-WinDialog{
	param(
	[string]$name
	)
	if($name -eq "Env"){
		start "$Env:windir\System32\rundll32.exe" -ArgumentList "sysdm.cpl,EditEnvironmentVariables" 
	}elseif($name -eq "Downloads"){
		start "$Env:userprofile\$name"
	}
}
set-alias od Open-WinDialog

function GoTo-Location {
	param(
	[string]$name
	)
	if($name -eq "Downloads"){
		Set-Location $Env:userprofile\Downloads
	}elseif($name -eq "WinDir"){
	    Set-Location $Env:Windir
	}elseif($name -eq "IIS"){
		Set-Location  IIS:	
	 }elseif($name -eq "modules"){
		$par =  $env:PSModulePath
		set-Location (($par -split ";")[0])
	 }
	 
}
function Edit-HostsFile{
notepad.exe C:\windows\System32\Drivers\etc\hosts
}
Set-Alias ehosts Edit-HostsFile
Set-Alias gt GoTo-Location

Set-Alias installUtil  $env:windir\Microsoft.net\framework\v4.0.30319\installutil
function Git-AddWarn { & git add -n .}
set-alias gitwarn git-addwarn
cd C:\
cls
