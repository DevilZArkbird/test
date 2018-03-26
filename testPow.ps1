function Color
{
	param 
	(
	[parameter(Mandatory=$true)]
	 [ValidateNotNullOrEmpty()]$Value,
	 [parameter(Mandatory=$true)]
	 [ValidateNotNullOrEmpty()]$Description
	)

	if($Value -eq $false)
		{

		Write-Host "Test : $Description --------------------------------------------- [False]" -ForegroundColor Red
		}

	if($Value -eq $true)
		{
		Write-Host "Test : $Description --------------------------------------------- [True]" -ForegroundColor Green
		}

}

function Test-Value
{
	param 
	(
	 [parameter(Mandatory=$true)]
	 [ValidateNotNullOrEmpty()]$Path,
	 
	[parameter(Mandatory=$true)]
	 [ValidateNotNullOrEmpty()]$Info,
	 
	[parameter(Mandatory=$true)]
	 [ValidateNotNullOrEmpty()]$Mode
	)
	
	if($Mode -eq "Check")
	{
		$Pass=Test-Path -Path $Path
		Return $Pass
	}
	if($Mode -eq "Info")
	{
		$tmp=Get-ItemProperty -Path $Path
        $a=$tmp.$Info
        Return $a
	}
	if($Mode -eq "File")
	{
		$ValueTest=$env:windir+$Path
		$Pass=Test-Path -Path $ValueTest
		Return $Pass
	}
}

function DetectCoreArtifacts
{
	Write-Host "`nCore Tests`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
	
				  $Description= ""
				  $Num=0
				  $Result = $False
				  $cpudata = Get-WmiObject -class win32_processor			
				  $NumPhyCores=$cpudata.NumberOfCores	
				  $NumLogCores=$cpudata.NumberOfLogicalProcessors
				  $L2CacheSize=$cpudata.L2CacheSize	
				  $L3CacheSize=$cpudata.L3CacheSize
				   
				If($NumPhyCores -eq $NumLogCores)
				{
					$Description= "Nombre de coeurs physique = Nombre de coeurs logiques"
					$result=$True
					Color $result $Description
				}
				
				Else
				{
					$Description= "Nombre de coeurs physique = Nombre de coeurs logiques"
					$result=$False
					Color $result $Description
				}
				
				if($NumLogCores -eq 1)
				{
					$Description= "Nombre de coeurs logiques est égal à 1"
					$result=$True
					Color $result $Description
				}	
				 Else
				 {
					$Description= "Nombre de coeurs logiques est égal à 1"
					$result=$False
					Color $result $Description
				 }
				
				 If($L3CacheSize -eq "0" -or $L3CacheSize -eq $null )
				 {
					If($L2CacheSize -eq "0" -or $L2CacheSize -eq $null)
					{
					$Description= "Cache CPU égal 0"
					$result=$True
					Color $result $Description
					}
				 }
				 Else
				 {
					$Description= "Cache CPU égal 0"
					$result=$False
					Color $result $Description
				 }	
}

function DetectSystemBios
{
Write-Host "`nSystem Bios `n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
$result=$False

$a=Test-Value -Path registry::"HKLM\HARDWARE\DESCRIPTION\System\" -Info "SystemBiosVersion" -Mode "Info"
if($a -match "VBOX")
{
$result=$True
Color -Value $result -Description "SystemBiosVersion Virtualbox"
}
else
{
$result=$False
Color -Value $result -Description "SystemBiosVersion Virtualbox"
}
if($a -match "Hyper-V UEFI Release" -Or $a -match "VRTUAL")
{
$result=$True
Color -Value $result -Description "SystemBiosVersion Hyper-V"
}
else
{
$result=$False
Color -Value $result -Description "SystemBiosVersion Hyper-V"
}

$a=Test-Value -Path registry::"HKLM\HARDWARE\DESCRIPTION\System\" -Info "SystemBiosDate" -Mode "Info"
if($a -match "/99")
{
$result=$True
Color -Value $result -Description "SystemBiosDate Virtualbox"
}
else
{
$result=$False
Color -Value $result -Description "SystemBiosDate Virtualbox"
}

$a=Test-Value -Path registry::"HKLM\HARDWARE\DESCRIPTION\System\" -Info "VideoBiosVersion" -Mode "Info"
if($a -match "Oracle VM VirtualBox")
{
$result=$True
Color -Value $result -Description "VideoBiosVersion Virtualbox"
}
else
{
$result=$False
Color -Value $result -Description "VideoBiosVersion Virtualbox"
}



}

function DetectRegistryArtifacts
{

Write-Host "`nRegistry Virtualbox`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\DSDT\VBOX__" -Info "null" -Mode "Check" 
Color -Value $a -Description "HKLM\HARDWARE\ACPI\DSDT\VBOX__"
$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\FADT\VBOX__" -Info "null" -Mode "Check" 
Color -Value $a -Description "HKLM\HARDWARE\ACPI\FADT\VBOX__"
$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\RSDT\VBOX__" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\HARDWARE\ACPI\RSDT\VBOX__"
$a=Test-Value -Path registry::"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions"
$a=Test-Value -Path registry::"HKLM\SYSTEM\ControlSet001\Services\VBoxGuest" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SYSTEM\ControlSet001\Services\VBoxGuest"
$a=Test-Value -Path registry::"HKLM\SYSTEM\ControlSet001\Services\VBoxMouse" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SYSTEM\ControlSet001\Services\VBoxMouse"
$a=Test-Value -Path registry::"HKLM\SYSTEM\ControlSet001\Services\VBoxService" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SYSTEM\ControlSet001\Services\VBoxService"
$a=Test-Value -Path registry::"HKLM\SYSTEM\ControlSet001\Services\VBoxSF" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SYSTEM\ControlSet001\Services\VBoxSF"
$a=Test-Value -Path registry::"HKLM\SYSTEM\ControlSet001\Services\VBoxVideo" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SYSTEM\ControlSet001\Services\VBoxVideo"

Write-Host "`nRegistry VMware`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

$a=Test-Value -Path registry::"HKLM\SOFTWARE\VMware, Inc.\VMware Tools" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SOFTWARE\VMware, Inc.\VMware Tools"



Write-Host "`nRegistry Hyper-V `n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\DSDT\MSFTVM" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\HARDWARE\ACPI\DSDT\MSFTVM"
$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\RSDT\VIRTUAL\MICROSFT" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\HARDWARE\ACPI\RSDT\VIRTUAL\MICROSFT"
$a=Test-Value -Path registry::"HKLM\HARDWARE\ACPI\FADT\VIRTUAL\MICROSFT" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\HARDWARE\ACPI\FADT\VIRTUAL\MICROSFT"

Write-Host "`nRegistry Wine`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

$a=Test-Value -Path registry::"HKLM\SOFTWARE\Wine" -Info "null" -Mode "Check"
Color -Value $a -Description "HKLM\SOFTWARE\Wine"
}

function DetectFileSystemArtifacts
{
$ValueVirtual=@("\System32\drivers\VBoxMouse.sys","\System32\drivers\VBoxGuest.sys","System32\drivers\VBoxSF.sys","System32\drivers\VBoxVideo.sys","System32\vboxdisp.dll","System32\vboxhook.dll","System32\vboxmrxnp.dll","System32\vboxogl.dll","System32\vboxoglarrayspu.dll","System32\vboxoglcrutil.dll","System32\vboxoglerrorspu.dll","System32\vboxoglerrorspu.dll","System32\vboxoglfeedbackspu.dll","System32\vboxoglpassthroughspu.dll","System32\vboxservice.exe","System32\vboxtray.exe","System32\VBoxControl.exe")
$ValueVmware=@("\System32\drivers\vmmouse.sys","\System32\drivers\vmmouse.sys","\System32\vsocklib.dll","\System32\drivers\vm3dmp.sys","\System32\drivers\vmci.sys","\System32\drivers\vmmemctl.sys","\System32\drivers\vmrawdsk.sys","\System32\drivers\vmusbmouse.sys")

Write-Host "`nFiles System Virtualbox`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	for($i=0; $i -le $ValueVirtual.Length -1; $i++)
	{
	$a=Test-Value -Path $ValueVirtual[$i] -Info "null" -Mode "File"
	Color -Value $a -Description $ValueVirtual[$i]
	}
Write-Host "`nFiles System VMware`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
	for($i=0; $i -le $ValueVmware.Length -1; $i++)
	{
	$a=Test-Value -Path $ValueVmware[$i] -Info "null" -Mode "File"
	Color -Value $a -Description $ValueVmware[$i]
	}
}

function DetectDirectoriesArtifacts
{
	Write-Host "`nDirectories`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	$TargetPath=@("\oracle\virtualbox guest additions\", "\VMWare\","\Hyper-V\")
	$Descriptiontab=@("Repertoires VirtualBox","Repertoires VMWare","Repertoires Hyper-V")
	for($i=0; $i -le $Descriptiontab.Length -1; $i++)
	{
		$Description=$Descriptiontab[$i]
		$ValueTest=$env:ProgramFiles+$TargetPath[$i]
		$Pass=Test-Path -Path $ValueTest
		Color $Pass $Description
	}

}

function DetectManufacturer
{
	$a=Get-WmiObject -Class Win32_ComputerSystem
	$NameManufacturer= $a.Manufacturer
	$NameModel=$a.Model
	Write-Host "`nManufacturer`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	if($NameManufacturer -match "Microsoft Corporation" -Or $NameModel -match "Virtual Machine" )
	{
		$Pass= $True
		$Description="Manufacturer Hyper-V"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Manufacturer Hyper-V"
		Color $Pass $Description
	}
	if($NameManufacturer -match "VMware, Inc." -Or $NameModel -match "VMware Virtual Platform" )
	{
		$Pass= $True
		$Description="Manufacturer VMware"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Manufacturer VMware"
		Color $Pass $Description
	}
	if($NameManufacturer -match "innotek GmbH" -Or $NameModel -match "VirtualBox" )
	{
		$Pass= $True
		$Description="Manufacturer VirtualBox"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Manufacturer VirtualBox"
		Color $Pass $Description
	}
	

}

function DetectStorageArtifacts
{
$a=  wmic diskdrive get Caption 
$CaptionDrive=$a[2]
$PassDrive=$False
Write-Host "`nStorage`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	if($CaptionDrive -match "Disque virtuel Microsoft")
	{
		$Pass= $True
		$Description="Virtual Disk Hyper-V"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Virtual Disk Hyper-V"
		Color $Pass $Description
	}
	if($CaptionDrive -match "VMware Virtual")
	{
		$Pass= $True
		$Description="Virtual Disk VMware"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Virtual Disk VMware"
		Color $Pass $Description
	}
	if($CaptionDrive -match "VBOX")
	{
		$Pass= $True
		$Description="Virtual Disk VirtualBox"
		Color $Pass $Description
	}
	else
	{
		$Pass= $False
		$Description="Virtual Disk VirtualBox"
		Color $Pass $Description
	}
	
	$a= wmic diskdrive | where{$_.Size -le 3000000000 }| where{$Passdrive=$True}
	$Description="Taille du disque inférieur à 30go"
	Color $PassDrive $Description	
	
}

function DetectNetworkArtifacts
{
Write-Host "`nNetwork Adapters`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

$PassVMware=$False
$PassHyperV =$False
$PassVirtualBox=$False

$a = get-wmiobject -class "Win32_NetworkAdapterConfiguration" |Where{$_.IpEnabled -Match "True"} | Where{$_.MACAddress -match "00:05:69" -Or $_.MACAddress -match "00:0C:29" -Or $_.MACAddress -match "00:1C:14" -Or $_.MACAddress -match "00:50:56"} | Foreach {$PassVMware=$True}
$a = get-wmiobject -class "Win32_NetworkAdapterConfiguration" |Where{$_.IpEnabled -Match "True"} | Where{$_.MACAddress -match "08:00:27"} | Foreach {$PassVirtualBox=$True}
$a = get-wmiobject -class "Win32_NetworkAdapterConfiguration" |Where{$_.IpEnabled -Match "True"} | Where{$_.MACAddress -match "00:15:5D"} | Foreach {$PassHyperV=$True}

	$Description="Virtual Network Adapter VMware"
	Color $PassVMware $Description
	$Description="Virtual Network Adapter Hyper-V"
	Color $PassHyperV $Description
	$Description="Virtual Network Adapter VirtualBox"
	Color $PassVirtualBox $Description

}

function DetectServicesArtifacts
{
	Write-Host "`nServices`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	$PassVMware=$False
	$PassVirtualBox=$False
	$a=Get-Service -Name "VMware*" | Where {$_.Name -match "VMware" -Or $_.Name -match "VMTools"}| Foreach {$PassVMware=$True}
	$a=Get-Service -Name "V*" | Where {$_.Name -match "VBox"}| Foreach {$PassVirtualBox=$True}
	
	$Description="Services VMware"
	Color $PassVMware $Description
	$Description="Services VirtualBox"
	Color $PassVirtualBox $Description
	Write-Host "`n-------------------------------------------------------------------------------" -ForegroundColor Yellow

}

function DetectProcessArtifacts
{
	Write-Host "`nProcess`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	$Autoruns=$False
	$Dumpcap=$False	
	$Filemon =$False 
	$ImmunityDebugger=$False 
	$ImportREC =$False
	$IDA=$False
	$JoeBox=$False
	$HookExplorer =$False
	$OllyDBG=$False 
	$LordPE=$False
	$ProcessHacker =$False
	$PETools=$False
	$ProcessExplorer =$False 
	$ProcessMonitor =$False
	$PassVMware=$False 
	$PassVirtualBox=$False 
	$Regmon =$False
	$SysAnalyzer =$False
	$SysInspector=$False
	$TCPView =$False
	$WinDbg =$False
	$Wireshark =$False
	
	$a=Get-Process 
	$a| Where {$_.ProcessName -match "VBoxService" -Or $_.ProcessName -match "VBoxTray"}| Foreach {$PassVirtualBox=$True}
	$a| Where {$_.ProcessName -match "VGAuthService" -Or $_.ProcessName -match "vmacthlp" -Or $_.ProcessName -match "vmtoolsd"}| Foreach {$PassVMware=$True}
	$a| Where {$_.ProcessName -match "ollydbg"}| Foreach {$OllyDBG=$True}
	$a| Where {$_.ProcessName -match "autoruns"}| Foreach {$Autoruns=$True}
	$a| Where {$_.ProcessName -match "procexp"}| Foreach {$ProcessExplorer=$True}
	$a| Where {$_.ProcessName -match "dumpcap"}| Foreach {$Dumpcap=$True}
	$a| Where {$_.ProcessName -match "filemon"}| Foreach {$Filemon=$True}
	$a| Where {$_.ProcessName -match "ImmunityDebugger"}| Foreach {$ImmunityDebugger=$True}
	$a| Where {$_.ProcessName -match "idaq"}| Foreach {$IDA=$True}
	$a| Where {$_.ProcessName -match "HookExplorer"}| Foreach {$HookExplorer=$True}
	$a| Where {$_.ProcessName -match "ImportREC"}| Foreach {$ImportREC=$True}
	$a| Where {$_.ProcessName -match "PETools"}| Foreach {$PETools=$True}
	$a| Where {$_.ProcessName -match "LordPE"}| Foreach {$LordPE=$True}
	$a| Where {$_.ProcessName -match "SysInspector"}| Foreach {$SysInspector=$True}
	$a| Where {$_.ProcessName -match "sysAnalyzer" -Or $_.ProcessName -match "sniff_hit" -Or $_.ProcessName -match "proc_analyzer" }| Foreach {$SysAnalyzer=$True}
	$a| Where {$_.ProcessName -match "windbg"}| Foreach {$WinDbg=$True}
	$a| Where {$_.ProcessName -match "joeboxcontrol" -Or $_.ProcessName -match "joeboxserver"}| Foreach {$JoeBox=$True}
		
	$DescriptionValue=@("Vmware","VirtualBox","Ollydbg","Autoruns","Process Explorer","Dumpcap","Filemon","ImmunityDebugger","IDA","HookExplorer","ImportREC","PETools","LordPE","SysInspector","WinDbg","JoeBox")
	$ValueTab=@($PassVMware,$PassVirtualBox,$OllyDBG,$Autoruns,$ProcessExplorer,$Dumpcap,$Filemon,$ImmunityDebugger,$IDA,$HookExplorer,$ImportREC,$PETools,$LordPE,$SysAnalyzer,$WinDbg,$JoeBox)
	for($i=0; $i -le $DescriptionValue.Length -1; $i++)
	{
	$Description="Process "+$DescriptionValue[$i]
	Color $ValueTab[$i] $Description
	}

}

function DetectMouse
{
$PassMouse=$False
Add-Type -AssemblyName System.Windows.Forms

$p1 = [System.Windows.Forms.Cursor]::Position
Start-Sleep -Seconds 5  # or use a shorter intervall with the -milliseconds parameter
$p2 = [System.Windows.Forms.Cursor]::Position
if($p1.X -eq $p2.X -and $p1.Y -eq $p2.Y) 
	{
		$PassMouse=$True
	} 
else 
	{
		$PassMouse=$False
	}
Write-Host "`nMouse`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
	
$Description="Mouse movement"
Color $PassMouse $Description

}

function DetectICMP
{
	$IP="8.8.8.8"
	$PassICMP=$False
	$Pass=$False
	
	if (Test-Connection -ComputerName $IP -Quiet)
	{	
		$Pass = $True
	}
	Else
	{
		$PassICMP=$False
	}
	Write-Host "`nICMP`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow

	$Description="ICMP"
	Color $PassICMP $Description
	$Description="ICMP Size"
	Color $PassICMP $Description
}

function EvadeTime
{
	for($i=1; $i -le 100; $i++)
	{
	Start-Sleep -s 3
	}
}

function DetectSoftwareInstalled
{
	
Write-Host "`nSoftwares Installed`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
	$IDA=$False
	$OllyDBG=$False
	$ImmunityDebugger=$False
	$PassVMware=$False
	
	$a=Get-WmiObject -Class Win32_Product | Select-Object -Property Name
	$a| Where {$_.Name -match "ida"}| Foreach {$IDA=$True}
	$a| Where {$_.Name -match "OllyDbg"}| Foreach {$OllyDBG=$True}
	$a| Where {$_.Name -match "ImmunityDebugger"}| Foreach {$ImmunityDebugger=$True}
	$a| Where {$_.Name -match "VMware"}| Foreach {$PassVMware=$True}
	
	$Description= "IDA installed"
	Color $IDA $Description
	$Description= "OllyDBG installed"
	Color $OllyDBG $Description
	$Description= "Immunity Debugger installed"
	Color $ImmunityDebugger $Description
	$Description= "VMware Tools installed"
	Color $PassVMware $Description
}
	
function Encode64
{
[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true
		)]
		[String]$Data
		)

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data)
$EncodedText =[Convert]::ToBase64String($Bytes)
return $EncodedText			
}

function Decode64
{
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true
		)]
		[String]$Data
		)		
		$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Data))
return 	$DecodedText
}			
function TestBase64
{
$Res=Encode64 "This is a secret and should be hidden"
Write-Host "`nEncode`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
$Res
Write-Host "`nDecode`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow		
Decode64 $Res
}

function Create-AESObject($key, $IV) 
{
    $aesObject = New-Object "System.Security.Cryptography.AesManaged"
    $aesObject.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesObject.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesObject.BlockSize = 128
    $aesObject.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesObject.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesObject.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesObject.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesObject.Key = $key
        }
    }
    $aesObject
}

function Create-AesKey()
 {
    $aesObject = Create-AESObject
    $aesObject.GenerateKey()
    [System.Convert]::ToBase64String($aesObject.Key)
}

function Encrypt-String($key, $unencryptedString) 
{
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesObject = Create-AESObject $key
    $encryptor = $aesObject.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesObject.IV + $encryptedData
   # $aesObject.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) 
{
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesObject = Create-AESObject $key $IV
    $decryptor = $aesObject.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
   # $aesObject.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

function TestAES
{
$key = Create-AesKey
$unencryptedString = "test"
Write-Host "`nEncode AES`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
$encryptedString = Encrypt-String $key $unencryptedString
$encryptedString
Write-Host "`nDecodeAES`n-------------------------------------------------------------------------------`n" -ForegroundColor Yellow
$backToPlainText = Decrypt-String $key $encryptedString
$backToPlainText
}

function DetectionTest
{
	DetectSystemBios
	DetectManufacturer
	DetectCoreArtifacts
	DetectRegistryArtifacts
	DetectFileSystemArtifacts
	DetectDirectoriesArtifacts
	DetectProcessArtifacts
	DetectStorageArtifacts
	DetectNetworkArtifacts
	DetectServicesArtifacts
	DetectSoftwareInstalled
	DetectMouse
	DetectICMP
	TestBase64
	#Use .NET Framework 3.5 min
	TestAES
	# Timeout for 5min
	#EvadeTime

}

function Main
{
	DetectionTest
	Write-Host ""
}

Main
