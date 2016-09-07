#!/usr/bin/env python

import os
import sys
import argparse
import subprocess
import collections
import multiprocessing
from netaddr import IPNetwork
from multiprocessing.dummy import Pool as ThreadPool



class numr8(object):

  def __init__(self, directoryname="Systems", userlist="wordlists/users.txt", passlist="wordlists/passwds.list"):
    self.banner()
    self.makedir(directoryname)
    self.parseargs()
    self.userlist = userlist
    self.passlist = passlist
    self.dirname = directoryname
    self.quickresults = self.enumerate(directoryname)
    self.hostdict = {}
    self.hostdict = self.parseresults(self.quickresults, self.hostdict)
    #print self.hostdict
    for target in self.hostdict.keys():
      self.tryharder(target, self.hostdict[target])  

  def banner(self):
    print "====================="
    print "==      numr8      =="
    print "====================="
    print

  def parseargs(self):
    parser = argparse.ArgumentParser(prog='numr8.py', add_help=False)
    parser.add_argument('-i', dest = 'interface', help='Interface to use (default: eth0)', default="eth0")    
    parser.add_argument('-c', dest = 'cidr', nargs='?', help='CIDR netblock to use [optional]', default=None) 
    args = parser.parse_args()
    self.myaddr, self.mynetmask = self.getmyaddr(args.interface)
    self.netstart, self.cidr = self.getnet(self.myaddr, self.mynetmask)
    if args.cidr != None:
      self.cidr = args.cidr
    print self.cidr
    self.hosts=self.findotherips(args.interface, self.netstart, self.cidr, self.myaddr)

  def getmyaddr(self, i):
    # Let's grab the IP address for the iface supplied as an arg
    result = subprocess.check_output(['ifconfig', i]).split('\n')
    for item in result:
      if 'inet ' in item:
        return item.split()[1], item.split()[3]

  def getnet(self, addr, mask):
    addr = addr.split('.')
    mask = mask.split('.')
    netstart = '.'.join([str(int(addr[x]) & int(mask[x])) for x in range(0,4)])
    binary_str = ''
    for octet in mask:
      binary_str += bin(int(octet))[2:].zfill(8)
    cidr = str(len(binary_str.rstrip('0')))
    return netstart, cidr

  def findotherips(self, i, netaddr, mask, myip):
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

  def makedir(self, dirname):
    if not os.path.exists(dirname):
      os.makedirs(dirname)

  def enumerate(self, dirname):
    cwd = os.getcwd()
    print "Discovered %s targets." % len(self.hosts)
    print "Creating directories..."
    for ip in self.hosts:
      self.makedir(cwd + '/' + dirname + '/' + ip)
      self.makedir(cwd + '/' + dirname + '/' + ip + '/' + 'nmap-quick')
    os.chdir(cwd + '/' + dirname)
    pool = ThreadPool(8)
    print "Performing quick NMAP scans on %s targets..." % len(self.hosts)
    result = pool.map(self.quicknmap, self.hosts)
    print "Done."
    return result

  def quicknmap(self, target):
    # nmap -A -Pn 192.168.151.137 -oN 192-168-151-137-nmap-quick.txt
    cwd = os.getcwd()
    targetfn = cwd + '/' + target + '/' + 'nmap-quick/' + '-'.join(target.split('.')) + '-nmap-quick.txt'
    result = subprocess.check_output(['nmap', '-A', '-Pn', target, '-oN', targetfn])
    result = result.split('\n')
    return result

  def parseresults(self, results, hd):
    print "Processing results for %s targets..." % len(results)
    for target in results:
      # First, get IP
      ip = target[2].split()[4]
      print "Target: %s" % ip
      hd[ip] = {}
      # Next, find open ports
      ports = []
      for item in target:
        if "open  " in item: 
          #print item.split()
          ports.append(item.split())
      for item in ports:
        if item[2] in hd[ip].keys():
          hd[ip][item[2]].append(item[0].split('/')[0])
        else:
          hd[ip][item[2]] = [item[0].split('/')[0]]
    return hd

  def addprocess(self, method, arguments):
    p = multiprocessing.Process(target=method, args=(arguments,))	
    p.start() 

  def tryharder(self, target, data):
    # Let's go through the parsed data and further enumerate
    # based on service
    for service in data.keys():
      port = data[service]
      for p in port:
        if service == "http":
          self.addprocess(self.enum_http, [target, p, "http"])
        if service == "https" or service == "ssl":
          self.addprocess(self.enum_http, [target, p, "https"])
        if service == "ftp":
          self.addprocess(self.enum_ftp, [target, p])
        #if service == "ssh":
          #self.addprocess(self.enum_ssh, [target, p])
        #if "netbios" in service:
          #self.addprocess(self.enum_smb, [target, p])
          #self.addprocess(self.enum_nbtscan, [target, p])
          #self.addprocess(self.enum_enum4linux, [target, p])
        #if "snmp" in service:
          #self.addprocess(self.enum_snmp, [target, p])

  def enum_http(self, args):
    target = args[0]
    port = args[1]
    protocol = args[2]
    self.makedir(target + '/http')
    print "INFO: Detected web server on %s:%s" % (target, port)
    script = "python ../webnumr8.py {} {} {} {} {}".format(target, port, protocol, self.userlist, self.passlist)
    subprocess.call(script, shell=True)

  def enum_ftp(self, args):
    target = args[0]
    port = args[1]
    self.makedir(target + '/ftp')
    print "INFO: Detected ftp server on %s:%s" % (target, port)
    script = "python ../ftpnumr8.py {} {} {} {}".format(target, port, self.userlist, self.passlist)
    subprocess.call(script, shell=True)

  os.system('stty sane')



'''
    cwd = os.getcwd()
    targetfn = cwd + '/' + target 
    self.makedir(targetfn + '/' + 'http')
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
    result = subprocess.check_output(['dirb', 'http://%s' % target, '-o', targetfn, '-S', '-w'])
    # skipfish
    #print "  running skipfish on %s..." % target
    #targetfn = cwd + '/' + target + '/' + 'http/' + '-'.join(target.split('.')) + '-skipfish'
    #makedir(targetfn)
    #result = subprocess.check_output(['skipfish', '-S/usr/share/skipfish/dictionaries/complete.wl', '-u', '-o', targetfn, 'http://%s' % target])
    # nikto
    # nikto -host http://192.168.151.137 -o foo -F txt -C all -T x
    print "  running nikto scan on %s..." % target
    targetfn = cwd + '/' + target + '/' + 'nikto'
    self.makedir(targetfn)
    targetfn = cwd + '/' + target + '/' + 'nikto/' + '-'.join(target.split('.')) + '-nikto.txt'
    result = subprocess.check_output(['nikto', '-host', 'http://%s' % target, '-o', targetfn, '-F', 'txt', '-C', 'all', '-T', 'x'])
'''



  ###
  ### Should only perform enum4linux if smb present
  ### ditto nbt
  ### also need onesixtyone scans
  ###onesixtyone -c ./results/community -i ./results/UDP161-IP.txt >./results/SNMP-onesixty.txt
  ####Full SNMP Tree
  ###for word in $(cat ./results/UDP161-IP.txt);do snmpwalk -c public -v1 $word>./results/$word/$word-SNMPFullTree.txt  & done 
  ####Winuser
  ###for word in $(cat ./results/UDP161-IP.txt);do snmpwalk -c public -v1 $word 1.3.6.1.4.1.77.1.2.25 >./results/$word/$word-SNMPWinUser.txt  & done 
  ####Enumerating Running Windows Processes
  ###echo Enumerating Running Windows Processes
  ###for word in $(cat ./results/UDP161-IP.txt);do snmpwalk -c public -v1 $word 1.3.6.1.2.1.25.4.2.1.2 >./results/$word/$word-SNMPWinProcess.txt  & done 
  ####Enumerating Open TCP Ports:
  ###echo Enumerating Open TCP Ports
  ###for word in $(cat ./results/UDP161-IP.txt);do snmpwalk -c public -v1 $word 1.3.6.1.2.1.6.13.1.3 >./results/$word/$word-SNMPWinTCPPorts.txt  & done 
  ####Enumerating Installed Software:
  ###echo Enumerating Installed Software
  ###for word in $(cat ./results/UDP161-IP.txt);do snmpwalk -c public -v1 $word 1.3.6.1.2.1.25.6.3.1.2 >./results/$word/$word-SNMPWinInstalledSoftware.txt  & done

  ### Look at http://www.backtrack-linux.org/wiki/index.php/Pentesting_VOIP#Information_Gathering
  ### for SIP enumeration techniques

  #print "Performing enum4linux scans on %s targets..." % len(iplist)
  # enum4linux apparently doesn't like being run multithreaded.  Have to iterate instead.
  #
  #result3 = pool.map(enum_enum4linux, iplist)
  #print "Done."
  #
  # Apparently, nbtscan doesn't like it, either.
  #print "Performing nbtscan scans on %s targets..." % len(iplist)
  #result4 = pool.map(enum_nbtscan, iplist)
  #print "Done."



  


def fullnmap(target):
  # nmap -A -Pn -p- 192.168.151.137 -oN 192-168-151-137-nmap-quick.txt
  cwd = os.getcwd()
  targetfn = cwd + '/' + target + '/' + 'nmap-full/' + '-'.join(target.split('.')) + '-nmap-full.txt'
  result = subprocess.check_output(['nmap', '-A', '-Pn', '-p-', target, '-oN', targetfn])
  return result


def enum_enum4linux(target):
  # enum4linux
  # enum4linux -a -l -d 192.168.151.142
  # It would seem that enum4linux does not like being run concurrently!
  print "  running enum4linux scan on %s..." % target
  cwd = os.getcwd()
  targetfn = cwd + '/' + target + '/' + 'enum4linux'
  makedir(targetfn)
  targetfn = cwd + '/' + target + '/' + 'enum4linux/' + '-'.join(target.split('.')) + '-enum4linux.txt'
  result = subprocess.check_output(['enum4linux', '-a', '-l', target  ])
  f = open(targetfn, 'w')
  for line in result:
    f.write(line)
  f.close()
  return result

def enum_nbtscan(target):
  #nbtscan -rvh 192.168.151.142
  print "  running nbtscan on %s..." % target
  cwd = os.getcwd()
  targetfn = cwd + '/' + target + '/' + 'nbtscan'
  makedir(targetfn)
  targetfn = cwd + '/' + target + '/' + 'nbtscan/' + '-'.join(target.split('.')) + '-nbtscan.txt'
  result = subprocess.check_output(['nbtscan', '-rvh', target ])
  f = open(targetfn, 'w')
  for line in result:
    f.write(line)
  f.close()
  return result





if __name__ == '__main__':
  numr8r = numr8()
