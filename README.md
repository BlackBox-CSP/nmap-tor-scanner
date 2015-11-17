### Standalone Nmap python app
```
    USAGE: nmap-tor.py <options>
    OPTIONS:
      -h, --help        Display this help message
      -t, --targets     Specify hosts to scan from a file or a
                         comma-separated list via CLI
      -p, --ports       Specify ports to scan from a file or a
                         comma-separated list via CLI
      -s, --sleep       Specify time in seconds to sleep between Nmap
                          requests (default:10)
      -n, --numhosts    Specify number of hosts to be randomly scanned
                          from the provided list
      --script          Specify NSE scripts to execute
    EXAMPLES:
      Scan google.com and 8.8.8.8 on TCP 80, 443, and 22:
          nmap-tor.py -t google.com,8.8.8.8 -p 80,443,22

      Scan 50 random hosts from the 4.2.2.0/24 network on port 53:
          nmap-tor.py -t 4.2.2.0/24 -p 53 -n 50

      Scan hosts/networks in hosts.txt on the ports from ports.txt:
          nmap-tor.py -t hosts.txt -p ports.txt -s 15 -n 50

      Scan www.google.com on port 80 and run the "http-title" NSE script
          nmap-tor.py -t www.google.com -p 80 --script http-title
```