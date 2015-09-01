#!/usr/bin/python

#from TorCtl import TorCtl
import sys
import socket
import socks
import httplib
from stem import Signal
from stem.control import Controller

def connectHeroku():
	conn = httplib.HTTPConnection("my-ip.herokuapp.com")
        conn.request("GET", "/")
        response = conn.getresponse()
        print(response.read())

def connectTor():
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
	socket.socket = socks.socksocket

def newIdentity():
	#disconnect from Tor before issuing commands
	socks.setdefaultproxy()
	with Controller.from_port(port = 9051) as controller:
		controller.authenticate()
		controller.signal(Signal.NEWNYM)
	connectTor()

def main():
	connectTor()
	print("Connected to Tor")
	connectHeroku()

	newIdentity()
	connectHeroku()

if __name__ == "__main__":
	main()

