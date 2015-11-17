#!/usr/bin/python
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
import re
import dns.resolver
import dns.exception

hostlist = []
num_targets = 0
num_hosts = 0
total_scan_operations = 0
targets_scanned = 0
first_run = True
sleep_time = 10
results_dict = {}
scripts = ['']
script_args = ''
scripts_running = False

# helper functions
def process_nmap_scan(port_scanner):
    """
    Convert the relevant dict results from the nmap scan to a dict that
    persists across scans
    """
    global results_dict
    # Check if there's already an entry saved for this host. If there is, avoid overwriting it
    if results_dict.has_key(target):
        # Check if there's already an entry saved for this port. If there is, avoid overwriting it
        if results_dict[str(target)]['tcp'].has_key(int(dest_port)):
            try:
                current_script_name = port_scanner[str(target)]['tcp'][int(dest_port)]['script'].keys()[0]
                current_script_output = port_scanner[str(target)]['tcp'][int(dest_port)]['script'].values()[0]
                results_dict[str(target)]['tcp'][int(dest_port)]['script'][current_script_name] = current_script_output
            # Exception if there was no script output, or there was no "script" dict in which to save the script results
            except KeyError:
                # Create the missing script dict (this is needed due to the first result for this port not having script
                # output, so the script portion of the results_dict structure isn't created)
                if port_scanner[str(target)]['tcp'][int(dest_port)].has_key('script'):
                    results_dict[str(target)]['tcp'][int(dest_port)]['script'] = {}
                    results_dict[str(target)]['tcp'][int(dest_port)]['script'][current_script_name] = current_script_output
                else:
                    pass
        # Create the entry for this port by copying the port dict from the port_scanner results
        else:
            results_dict[str(target)]['tcp'][int(dest_port)] = port_scanner[target]['tcp'][int(dest_port)]
    # Create the entry for this host because it doesn't exist
    else:
        results_dict[str(target)] = port_scanner[str(target)]

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
                print ("[!] Warning: Invalid address or netmask: '" + target_line + "'")
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
    print'    USAGE: nmap-tor.py <options>'
    print'    OPTIONS:'
    print'      -h, --help        Display this message'
    print'      -t, --targets     Specify hosts to scan from a file or comma'
    print'                          separated list'
    print'      -p, --ports       Specify file of ports to be used on target'
    print'      -s, --sleep       Specify time in seconds to sleep between Nmap'
    print'                          requests (default:10)'
    print'      -n, --numhosts    Specify number of hosts to be randomly scanned'
    print'                          from the provided list'
    print'    EXAMPLES:'
    print'      Scan google.com and 8.8.8.8 on TCP 80, 443, and 22:'
    print'          nmap-tor.py -t google.com,8.8.8.8 -p 80,443,22\n'
    print'      Scan 50 random hosts from the 4.2.2.0/24 network on TCP 53:'
    print'          nmap-tor.py -t 4.2.2.0/24 -p 53 -n 50\n'
    print'      Scan hosts/networks in hosts.txt on the ports from ports.txt:'
    print'          nmap-tor.py -t hosts.txt -p ports.txt -s 15 -n 50\n'

def print_script_output(host, script = 'all'):
    """
    Prints the script outputs that are stored in the results_dict dictionary
    """
    if results_dict[host]['tcp'][int(dest_port)].has_key('script'):
        if script == 'all':
            scriptnames = results_dict[host]['tcp'][int(dest_port)]['script'].keys()
        else:
            scriptnames = [script]
        for scriptname in scriptnames:
            print "| " + scriptname
            try:
                scriptvalue = results_dict[host]['tcp'][int(dest_port)]['script'][scriptname]
                count = 1
                for line in scriptvalue.lstrip().split('\n'):
                    if count < len(scriptvalue.lstrip().split('\n')):
                        print "|   " + line.lstrip()
                    else:
                        print "|_  " + line.lstrip()
                    count += 1
            except KeyError:
                print "|_  No script output"
    else:
        print "|_  No script output"

# System arguments for input and output files
try:
    opts, args = getopt.getopt(sys.argv[1:], "ht:p:s:n:", ["help", "targets=", "ports=", "sleep=", "numhosts=",
                                                           "script=", "script-args="])
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
    elif opt in ("-t", "--targets"):
        inputfile = arg
        if os.path.isfile(inputfile):
            try:
                with open(inputfile) as hostfile:
                    for host in hostfile:
                        hostlist.append(host)
            except:
                sys.exit("Input file for hosts is not valid")
        else:
            for host in inputfile.split(","):
                hostlist.append(host)
        # Check that all hosts are valid IPs or hostnames
        temp_hostlist = hostlist
        for host in temp_hostlist:
            # Regex matches ip addresses and cidr notation for networks
            if re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/[0-9][0-9]?)?$", host):
                pass
            else:
                try:
                    dns.resolver.query(host, "A")
                except dns.exception.DNSException:
                    print "[!] Warning: unable to resolve host '" + host.rstrip() + "' - Skipping"
                    hostlist.remove(host)
    elif opt in ("-p", "--ports"):
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
    elif opt in ("-n", "--numhosts"):
        num_hosts = int(arg)
    elif opt in ("-s", "--sleep"):
        sleep_time = float(arg)
    elif opt in ("--script"):
        scripts = []
        for script in arg.split(','):
            scripts.append(script)
            scripts_running = True
    elif opt in ("--script-args"):
        script_args = " --script-args=" + arg

print "[+] Nmap-Tor-Scanner starting up...\n"
targetlist = refine_targetlist(hostlist)
total_scan_operations = len(targetlist) * len(targetports) * len(scripts)

nmscanner = nmap.PortScanner()

for target in targetlist:
    for dest_port in targetports:
        for script in scripts:
            arguments = ' -sT -Pn --unprivileged'
            if scripts_running:
                arguments = " --script=" + script + script_args + arguments
            if not first_run:
                print "[+] Sleeping for " + str(sleep_time) + " seconds..."
                time.sleep(sleep_time)
                tor.changeIP()
            else:
                first_run = False
            print(query("https://www.atagar.com/echo.php"))
            sys.stdout.write("Trying {0:s} on TCP {1:s}".format(target, dest_port))
            if scripts_running:
                sys.stdout.write(" with script '" + script + "'...\n")
            else:
                sys.stdout.write("...\n")
            nmscanner.scan(target, str(dest_port), arguments)
            targets_scanned += 1
            process_nmap_scan(nmscanner)
            print "TCP " + str(dest_port) + " is " + nmscanner[target]['tcp'][int(dest_port)]["state"].upper() + " on " + target

            # Output script info during scan
            if scripts_running:
                print "Script:"
                print_script_output(target, script)

            print "\n[+] (" + str(targets_scanned) + "/" + str(total_scan_operations) + ") " + \
                   str(round((targets_scanned/float(total_scan_operations))*100, 1)) + "% completed"

# Print a summary if there are multiple hosts being scanned
if len(targetlist) > 1:
    print "\n" + "-" * 40
    print "Summary:"
    for host in results_dict.viewkeys():
        print "\n" + host
        for port in results_dict[host]['tcp'].viewkeys():
            print "    TCP " + str(port) + ' ' + results_dict[host]['tcp'][port]['state'].upper()
            if scripts_running:
                print_script_output(host)

print "\n[+] Nmap-Tor-Scanner exiting"
