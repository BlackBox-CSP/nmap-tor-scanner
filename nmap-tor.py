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
import os.path
__author__ = 'jbollin'

hostlist = []
num_targets = 0
num_hosts = 0
total_targets_and_hosts = 0
targets_scanned = 0
first_run = True
sleep_time = 10

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
    # Use only a certain number of random hosts if user specified -n
    if num_hosts > 0:
        outputlist = outputlist[0:num_hosts]
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
        print "[*] Exiting check tor service to see if it is started...\n"
        sys.exit("Unable to reach %s (%s)" % (url, exc))


def printhelp():
    print'    usage: ./nmap-tor.py <options>'
    print'    options:'
    print'      -h, --help        Display this message'
    print'      -t, --target      Specify single IP address or network of target'
    print'      -f, --targetlist  Specify file of IP addresses and/or networks to use as target'
    print'      -p, --portlist    Specify file of ports to be used on target'
    print'      -s, --sleep       Specify time in seconds to sleep between Nmap requests (default:10)'
    print'      -n, --numhosts    Specify number of hosts to be scanned from the provided list'

# System arguments for input and output files
try:
    opts, args = getopt.getopt(sys.argv[1:], "hf:t:p:s:n:", ["help", "target=", "targetlist=",
                                                           "portlist=", "sleep=", "numhosts="])
except getopt.GetoptError:
    print printhelp()
    sys.exit(2)
if len(opts) == 0:
    printhelp()
    sys.exit("\nError: There were no arguments specified\n")
for opt, arg in opts:
    if opt in ("-h", "--help"):
        print printhelp()
        sys.exit(2)
    elif opt in ("-f", "--targetlist"):
        inputfile = arg
        if os.path.isfile(inputfile):
            try:
                with open(inputfile) as hostfile:
                    hostlist = []
                    for host in hostfile:
                        hostlist.append(host)
            except:
                sys.exit("Input file for hosts is not valid")
        else:
            for host in inputfile.split(","):
                hostlist.append(host)
    elif opt in ("-p", "--portlist"):
        inputfile = arg
        targetports = []
        if os.path.isfile(inputfile):
            try:
                with open(inputfile) as portfile:

                    for port in portfile:
                        targetports.append(port.strip('\r\n'))
                    num_ports = len(targetports)
            except:
                sys.exit("Input file for ports is not valid")
        else:
            for host in inputfile.split(","):
                try:
                    if int(host.strip()) in range(0,65536):
                        targetports.append(host)
                    else:
                        raise ValueError
                except ValueError:
                    print "[!] Warning: Invalid port specified: '" + str(host) + "'"
    elif opt in ("-t", "--target"):
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
    elif opt in ("-n", "--numhosts"):
        num_hosts = int(arg)
    elif opt in ("-s", "--sleep"):
        sleep_time = float(arg)

print "[+] Nmap-Tor-Scanner starting up...\n"
targetlist = refine_targetlist(hostlist)
total_targets_and_hosts = len(targetlist) * len(targetports)

for target in targetlist:
    for dest_port in targetports:
        if not first_run:
            print "[+] Sleeping for " + str(sleep_time) + " seconds..."
            time.sleep(sleep_time)
            tor.changeIP()
        else:
            first_run = False
        print(query("https://www.atagar.com/echo.php"))
        print "trying {0:s} on {1:s}".format(target, dest_port)
        nmap.print_scan(nmap.do_scan(target, '-sT -p ' + str(dest_port)))
        targets_scanned += 1
        print "\n[+] (" + str(targets_scanned) + "/" + str(total_targets_and_hosts) + ") " + \
              str(round((targets_scanned/float(total_targets_and_hosts))*100, 1)) + "% targets scanned"
