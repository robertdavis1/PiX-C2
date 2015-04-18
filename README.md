PiX-C2 ICMP C2 server application
written by NoCow 
email: robert.ant.davis@gmail.com

The ICMP C2 project (ie PiX-C2) is a client/server application that allows for command and control using only ICMP. The server will sniff ICMP packets and pull information from the data payload of the ICMP packet. 
If the proper data is received, a command is sent to the client. Command must 
start with "run <command>". Other server options include sleep, sysinfo, more to come.

ASSUMPTIONS:
* You have root/admin privs on client/server machine
* Python/Scapy are installed on client/server machine
* Mysql installed

COMPONENTS:
* pix-s ~ Server component; must be able to sniff ICMP packets off the wire; disable ICMP reply at OS level
* pix-c ~ client component; must have admin rights to manipulate raw sockets and packets; tested in Ubuntu; python required
* powerpix-c ~ client component (powershell); still developing this, but will eventually be an in-memory powershell version of pix-c


run install.sh to install database schema and user/password for master (pix-s.py) app.

Disclaimer: This application must not be used for illegal purposes. Get explicit permission before use.
