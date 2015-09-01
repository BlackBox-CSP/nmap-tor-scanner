'''
make sure that you do this first
sudo apt-get install libssl-dev libcurl4-openssl-dev python-dev
pip install pycurl --upgrade

Dont start tor this starts/stops tor automatically
'''

import io
import pycurl

import stem.process
from stem import Signal
from stem.util import term
from stem.control import Controller


SOCKS_PORT = 7000

def changeIP():
    print("[+] Changing IP Address...")
    with Controller.from_port(port = 9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print(term.format(line, term.Color.BLUE))

def query(url):
  """
  Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
  """

  output = io.BytesIO()

  query = pycurl.Curl()
  query.setopt(pycurl.URL, url)
  query.setopt(pycurl.PROXY, 'localhost')
  query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
  query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
  query.setopt(pycurl.WRITEFUNCTION, output.write)

  try:
    query.perform()
    return output.getvalue()
  except pycurl.error as exc:
    return "Unable to reach %s (%s)" % (url, exc)


# Start an instance of Tor configured to only exit through Russia. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.


print(term.format("Starting Tor:\n", term.Attr.BOLD))
tor_process = stem.process.launch_tor_with_config(
    config = {'SocksPort': str(SOCKS_PORT),
              'ControlPort': str('9051')
             },
    init_msg_handler = print_bootstrap_lines)
print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
print(term.format(query("https://www.atagar.com/echo.php"), term.Color.BLUE))
changeIP()
print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
print(term.format(query("https://www.atagar.com/echo.php"), term.Color.BLUE))
tor_process.kill()