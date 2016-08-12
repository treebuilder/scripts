#!/usr/bin/env python

import os
import sys
import subprocess
import collections
from netaddr import IPNetwork
from multiprocessing.dummy import Pool as ThreadPool

# We need to know which interface we're using.
IFACE = sys.argv[1]

# structure: ipaddr:{servicename:ports}
HOSTDICT = {}


def getmyaddr(i):
  # Let's grab the IP address for the iface supplied as an arg
  result = subprocess.check_output(['ifconfig', i]).split('\n')
  for item in result:
    if 'inet ' in item:
      return item.split()[1], item.split()[3]

def getnet(addr, mask):
  addr = addr.split('.')
  mask = mask.split('.')
  netstart = '.'.join([str(int(addr[x]) & int(mask[x])) for x in range(0,4)])
  binary_str = ''
  for octet in mask:
    binary_str += bin(int(octet))[2:].zfill(8)
  cidr = str(len(binary_str.rstrip('0')))
  return netstart, cidr

def findotherips(i,netaddr,mask, myip):
  # Get the IP addresses of devices on the local net for the specified iface
  # nmap -sn -n -T4 192.168.151.0/24
  # netdiscover -i iface -r CIDR -P -N
  range = netaddr + '/' + mask
  # We need to remove the first and almost-last IP from the list, because VMWare.
  first = str(list(IPNetwork(range))[1])
  last = str(list(IPNetwork(range))[-2])
  result = subprocess.check_output(['nmap','-sn', '-n', '-T4', range])
  result = result.split('\n')
  ips = []
  for i in result:
    ip = None
    mac = None
    #Nmap scan report for 192.168.151.1
    #Host is up (0.00018s latency).
    #MAC Address: 00:50:56:C0:00:01 (VMware)
    if "Nmap scan report" in i:
      ip = i.split()[4]
      if ip != myip and ip != first and ip != last:
        ips.append(ip)
      continue
  return ips
      
def makedir(dirname):
  if not os.path.exists(dirname):
    os.makedirs(dirname)

def quicknmap(target):
  # nmap -A -Pn 192.168.151.137 -oN 192-168-151-137-nmap-quick.txt
  cwd = os.getcwd()
  targetfn = cwd + '/' + target + '/' + 'nmap-quick/' + '-'.join(target.split('.')) + '-nmap-quick.txt'
  result = subprocess.check_output(['nmap', '-A', '-Pn', target, '-oN', targetfn])
  result = result.split('\n')
  return result

def fullnmap(target):
  # nmap -A -Pn -p- 192.168.151.137 -oN 192-168-151-137-nmap-quick.txt
  cwd = os.getcwd()
  targetfn = cwd + '/' + target + '/' + 'nmap-full/' + '-'.join(target.split('.')) + '-nmap-full.txt'
  result = subprocess.check_output(['nmap', '-A', '-Pn', '-p-', target, '-oN', targetfn])
  return result


'''
[['', 'Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2016-08-11 11:08 EDT', 'Nmap scan report for 192.168.151.137', 'Host is up (0.00039s latency).', 'Not shown: 997 closed ports', 'PORT   STATE SERVICE VERSION', '21/tcp open  ftp     vsftpd 2.0.8 or later', '22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)', '| ssh-hostkey: ', '|   1024 82:fe:93:b8:fb:38:a6:77:b5:a6:25:78:6b:35:e2:a8 (DSA)', '|_  256 91:b8:6a:45:be:41:fd:c8:14:b5:02:a0:66:7c:8c:96 (ECDSA)', '80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))', '|_http-server-header: Apache/2.2.22 (Ubuntu)', "|_http-title: Site doesn't have a title (text/html).", 'MAC Address: 00:0C:29:37:E5:25 (VMware)', 'Device type: general purpose', 'Running: Linux 2.6.X|3.X', 'OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3', 'OS details: Linux 2.6.32 - 3.10', 'Network Distance: 1 hop', 'Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel', '', 'TRACEROUTE', 'HOP RTT     ADDRESS', '1   0.39 ms 192.168.151.137', '', 'OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .', 'Nmap done: 1 IP address (1 host up) scanned in 23.71 seconds', '']
'''

def parseresults(results,HOSTDICT):
  # build up HOSTDICT here
  print "Processing results for %s targets..." % len(results)
  for target in results:
    # First, get IP
    ip = target[2].split()[4]
    print "Target: %s" % ip
    # Next, find open ports
    ports = []
    for item in target:
      if "open  " in item: 
        ports.append(item.split())
    for item in ports:
      HOSTDICT[ip][item[2]] = item[0].split('/')[0]
  return
       
def enum_http(target, port):
  # We can run through NSE scripts here
  # maybe dirb, some nikto stuff
  # others?
  cwd = os.getcwd()
  targetfn = cwd + '/' + target 
  makedir(targetfn + '/' + 'http')
  scripts = ['http-enum', 'http-comments-displayer', 'http-headers']
  files = ['robots.txt', '.htaccess']
  for script in scripts:  
    print "  running %s NSE scan on %s..." % (script, target)
    targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-' + script + '.txt'
    result = subprocess.check_output(['nmap', '-Pn', '--script=%s' % script, target, '-oN', targetfn])
    if script == 'http-enum':
      for file in files:
        if file in result:
          print "    grabbing %s from %s..." % (file, target)
          targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-' + file
          result = subprocess.check_output(['wget', '-q', '-O', targetfn, 'http://%s/%s' % (target, file)])
  # dirb
  print "  running dirb scan on %s..." % target
  targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-dirb.txt'
  result = subprocess.check_output(['dirb', 'http://%s' % target, '-o', targetfn, '-S'])
  # skipfish
  print "  running skipfish on %s..." % target
  targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-skipfish'
  makedir(targetfn)
  result = subprocess.check_output(['skipfish', '-S/usr/share/skipfish/dictionaries/complete.wl', '-u', '-o', targetfn, 'http://%s' % target])
  # nikto
  # nikto -host http://192.168.151.137 -o foo -F txt -C all -T x
  print "  running nikto scan on %s..." % target
  targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-nikto.txt'
  result = subprocess.check_output(['nikto', '-host', 'http://%s' % target, '-o', targetfn, '-F', 'txt', '-C', 'all', '-T', 'x'])
        
  return

def enum_ftp(target, port):
  # nmap NSE,
  # what else?
  return

def enum_ssh(target, port):
  # more NSE.
  return

def enum_rpcinfo(target, port):
  # ???
  return

def tryharder(target, data):
  # Let's go through the parsed data and further enumerate
  # based on service
  for service in data.keys():
    port = data[service]
    if service == "http":
      results = enum_http(target, port) 
    if service == "ftp":
      results = enum_ftp(target, port)
    if service == "ssh":
      results = enum_ssh(target, port)
    if service == "rpcinfo":
      results = enum_rpcinfo(target, port)
  return
 

def main():
  # First, find out the IP address and netmask for the specified interface
  myaddr, mynetmask = getmyaddr(IFACE)
  # Compute the starting address and CIDR mask from that info
  netstart, cidr = getnet(myaddr,mynetmask)
  # Now, grab the IPs that respond to an ARP ping in that range
  iplist = findotherips(IFACE, netstart, cidr, myaddr)
  # With that, let's make directories and start scanning them!
  cwd = os.getcwd()
  HOSTDICT = collections.defaultdict(dict)
  print "Discovered %s targets." % len(iplist)
  print "Creating directories..."
  for ip in iplist:
    makedir(ip)
    os.chdir(cwd + '/' + ip)
    makedir('nmap-quick')
    os.chdir(cwd)
  pool = ThreadPool(8)
  print "Performing quick NMAP scans on %s targets..." % len(iplist)
  result = pool.map(quicknmap, iplist)
  print "Done."
  parseresults(result,HOSTDICT)
  for target in HOSTDICT.keys():
    tryharder(target, HOSTDICT[target])  



  # Because for some reason it's needed after the threading
  os.system('stty sane')
  




if __name__ == '__main__':
  main()
