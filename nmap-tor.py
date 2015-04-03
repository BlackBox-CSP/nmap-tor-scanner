__author__ = 'jbollin'

import ConfigParser
import getopt
import sys
import ipaddress
import write_excel
import random

hostlist = []
targetlist = []
num_hosts = 1


config = ConfigParser.ConfigParser()
config.read('scanner.cfg')
num_of_threads = int(config.get("Multithreading", "num_of_threads"))
source_port = int(config.get("Scanner", "source_port"))

#helper functions
def refine_targetlist(targets):
    global num_hosts
    outputlist = []
    num_targets = len(targets)
    while num_hosts > 0:
        outputlist.append(targets[random.randrange(0,num_targets)])
        num_hosts -= 1
    return(outputlist)

def start_scan():
    pass

def generate_workers():
    pass

def create_queue():
    pass

def validate_exit():
    pass

#System arguments for input and output files
try:
    opts, args = getopt.getopt(sys.argv[1:],"hf:o:m:t:n:")
except getopt.GetoptError:
    print "help message place holder"
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print "help message place holder"
        sys.exit()
    elif opt in ("-f"):
        inputfile = arg
        try:
            with open(inputfile) as hostfile:
                hostlist = []
                for host in hostfile:
                    hostlist.append(host)
                num_hosts = len(hostlist)
        except:
            sys.exit("input file is not valid")
    elif opt in ("-o"):
        outputfile = arg
    elif opt in ("-m"):
        num_of_queues = arg
    elif opt in ("-t"):
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
    elif opt in ("-n"):
        num_hosts = int(arg)


targetlist = refine_targetlist(hostlist)



