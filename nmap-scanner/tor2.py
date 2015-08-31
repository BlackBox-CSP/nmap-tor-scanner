#!/usr/bin/python

#from TorCtl import TorCtl
import sys
import socket
import socks
import httplib

def connectTor():
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
	socket.socket = socks.socksocket

def newIdentity():
	#disconnect from Tor before issuing commands
	socks.setdefaultproxy()
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("127.0.0.1", 9051))
	s.send("AUTHENTICATE\r\n")
	response = s.recv(128)
	if response.startswith("250"):
		s.send("SIGNAL NEWNYM\r\n")
	s.close()
	connectTor()

def main():
	connectTor()
	print("Connected to Tor")
	conn = httplib.HTTPConnection("my-ip.herokuapp.com")
	conn.request("GET", "/")
	response = conn.getresponse()
	print(response.read())

	newIdentity()
	conn = httplib.HTTPConnection("my-ip.herokuapp.com")
        conn.request("GET", "/")
        response = conn.getresponse()
        print(response.read())

if __name__ == "__main__":
	main()

