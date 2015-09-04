#!/usr/bin/python

from stem import Signal
from stem.util import term
from stem.control import Controller

def changeIP():
    print("[+] Changing IP Address...")
    with Controller.from_port(port = 9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
