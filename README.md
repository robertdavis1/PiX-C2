pingC2 ICMP C2 server application
written by NoCow 
email: robert.ant.davis@gmail.com

This is the server side application for the ICMP C2 project. The server will sniff ICMP packets and listen for the data payload of "What shall I do master?". If this data is received, a command is sent to the client. Command must start with "run"

TODO:
Complete - * Build sleep functionality into client/server
* Build shell functionality into client
* Build data exfil functionality into client
* Build database for system data collection
* Fix clean stop of server side 

Disclaimer: This application must not be used for illegal purposes. Get explicit permission before use.
