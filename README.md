pingC2 ICMP C2 server application
written by NoCow 
email: robert.ant.davis@gmail.com

The ICMP C2 project (ie pingc2) is a client/server application that allows for command and control using only ICMP. The server will sniff ICMP packets and pull information from the data payload of the ICMP packet. 
If the proper data is received, a command is sent to the client. Command must 
start with "run <command>". Other server options include sleep, sysinfo, more to come.

ASSUMPTIONS:
* You have root/admin privs on client/server machine
* Python/Scapy are installed on client/server machine
* Mysql installed and database configured (working on schema file)

Disclaimer: This application must not be used for illegal purposes. Get explicit permission before use.
