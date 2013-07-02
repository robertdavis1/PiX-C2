pingC2 ICMP C2 server application
written by NoCow 
email: robert.ant.davis@gmail.com

This is the server side application for the ICMP C2 project. The server will sniff ICMP packets and listen for the 
data payload of "What shall I do master?". If this data is received, a command is sent to the client. Command must 
start with "run <command>". Other server options include sleep, sysinfo, more to come.

ASSUMPTIONS:
* You have root/admin privs on client/server machine
* Python/Scapy are installed on client/server machine


TODO:
Complete - * Build sleep functionality into client/server
Complete - * Add client machine GUID for system tracking
* Build shell functionality into client
* Build data exfil functionality into client
Complete - * Build database for system data collection
Complete - * Fix clean stop of server side 
Complete - * Build sysinfo module and store data in database
Complete - * Build bot display
* Add ability to control single or groups of bots instead of global command


DONE:
* added ASCII art to pingc2
* added sniffer threading
* added ability to change botnet command on fly through command center
* added menu

Disclaimer: This application must not be used for illegal purposes. Get explicit permission before use.
