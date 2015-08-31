#!/usr/bin/python

import nmap
from netaddr import *
import pprint
import sys
import random

ip = IPAddress('192.168.1.254')
print ip.version

# Call nmap
nm = nmap.PortScanner()
nm.scan('192.168.1.254', '80')
print nm.command_line()
# Print results
for host in nm.all_hosts():
	print('------------------------------------')
	print ('Host : %s (%s)' % (host, nm[host].hostname()))
	print ('State : %s' % nm[host].state())
	for proto in nm[host].all_protocols():
		print ('----------')
		print ('Protocol : %s' % proto)
		lport = nm[host][proto].keys()
		lport.sort()
		for port in lport:
			print ('port: %s\tstate : %s' % (port, nm[host][proto][port]['state']))

