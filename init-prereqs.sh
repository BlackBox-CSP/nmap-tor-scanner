#!/bin/bash
apt-get --assume-yes install tor
echo "ControlPort 9051" >> /etc/tor/torrc
service tor start
apt-get --assume-yes install libssl-dev libcurl4-openssl-dev python-dev
apt-get --assume-yes install tsocks
echo '# This is the configuration for libtsocks (transparent socks) for use' > /etc/tsocks.conf
echo '# with tor, which is providing a socks server on port 9050 by default.' >> /etc/tsocks.conf
echo '#' >> /etc/tsocks.conf
echo '# See tsocks.conf(5) and torify(1) manpages.' >> /etc/tsocks.conf
echo ''>> /etc/tsocks.conf
echo 'server = 127.0.0.1' >> /etc/tsocks.conf
echo 'server_port = 9050' >> /etc/tsocks.conf
echo ''>> /etc/tsocks.conf
echo '# We specify local as 127.0.0.0 - 127.191.255.255 because the' >> /etc/tsocks.conf
echo '# Tor MAPADDRESS virtual IP range is the rest of net 127.' >> /etc/tsocks.conf
echo 'local = 127.0.0.0/255.128.0.0' >> /etc/tsocks.conf
echo 'local = 127.128.0.0/255.192.0.0' >> /etc/tsocks.conf
echo 'local = 127.128.0.0/255.192.0.0' >> /etc/tsocks.conf

pip install pycurl --upgrade
pip install stem
pip install python-libnmap

