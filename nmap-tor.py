#!/usr/bin/python
import ConfigParser
import getopt
import sys
import ipaddress
import random
import tor
import nmap
import time
import pycurl
import io
__author__ = 'jbollin'

hostlist = []
num_targets = 0
num_hosts = 0
first_run = True

config = ConfigParser.ConfigParser()
config.read('scanner.cfg')
source_port = int(config.get("Scanner", "source_port"))


# helper functions
def refine_targetlist(targets):
    """
    Extract host ips from network blocks and randomize host scan order
    """
    global num_hosts
    outputlist = []
    for target_line in targets:
        target_line = target_line.rstrip()
        if "/" in target_line:
            try:
                for address in (ipaddress.ip_network(unicode(target_line)).hosts()):
                    outputlist.append(str(address))
            except ValueError:
                sys.exit("Invalid address or netmask: " + target_line)
        else:
            outputlist.append(target_line)
    random.shuffle(outputlist)
    return outputlist


def query(url):
    """
    Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
    """
    socks_port = 9050
    output = io.BytesIO()

    curl_query = pycurl.Curl()
    curl_query.setopt(pycurl.URL, url)
    curl_query.setopt(pycurl.PROXY, 'localhost')
    curl_query.setopt(pycurl.PROXYPORT, socks_port)
    curl_query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    curl_query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
        curl_query.perform()
        return output.getvalue()
    except pycurl.error as exc:
        return "Unable to reach %s (%s)" % (url, exc)


def printhelp():
    print'    usage: ./nmap-tor.py <options>'
    print'    options:'
    print'      -h, --help          Display this message.'
    print'      -t, --target      specify single IP address or network of target'
    print'      -f, --targetlist  specify file of IP addresses and/or networks to use as target'
    print'      -p, --portlist    specify file of ports to be used on target'


# System arguments for input and output files
try:
    opts, args = getopt.getopt(sys.argv[1:], "hf:t:p:")
except getopt.GetoptError:
    print printhelp()
    sys.exit(2)
if len(args) < 0:
    printhelp()
    sys.exit("There are no arguments listed")
for opt, arg in opts:
    if opt == '-h':
        print printhelp()
        sys.exit(2)
    elif opt in "-f":
        inputfile = arg
        try:
            with open(inputfile) as hostfile:
                hostlist = []
                for host in hostfile:
                    hostlist.append(host)
                num_hosts = len(hostlist)
        except:
            sys.exit("Input file for hosts is not valid")
    elif opt in "-p":
        inputfile = arg
        try:
            with open(inputfile) as portfile:
                targetports = []
                for port in portfile:
                    targetports.append(port.strip('\r\n'))
                num_ports = len(targetports)
        except:
            sys.exit("Input file for ports is not valid")

    elif opt in "-t":
        try:
            arg_ucode = unicode(arg)
            target_subnet = ipaddress.IPv4Network(arg_ucode)
            iplist = list(ipaddress.ip_network(target_subnet).hosts())
            for ip in iplist:
                hostlist.append(str(ip.compressed))
        except ipaddress.AddressValueError:
            sys.exit('Invalid IP address')
        except ipaddress.NetmaskValueError:
            sys.exit('Invalid subnet mask')
    elif opt in "-n":
        num_hosts = int(arg)

print "[+] Nmap-Tor-Scanner starting up...\n"
targetlist = refine_targetlist(hostlist)

for target in targetlist:
    for dest_port in targetports:
        if not first_run:
            print "\n[+] Sleeping for 10 seconds..."
            time.sleep(10)
            tor.changeIP()
        else:
            first_run = False
        print(query("https://www.atagar.com/echo.php"))
        print "trying {0:s} on {1:s}".format(target, dest_port)
        nmap.print_scan(nmap.do_scan(target, '-sT -p ' + str(dest_port)))
