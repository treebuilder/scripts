import argparse
import time
import sys
import os
import subprocess

class ftpnumr8(object):
    def __init__(self):
        self.parseargs()
        self.nmap_nse(self.host, self.port)
        #self.bruteforce(self.host, self.port, self.userList, self.passList)

    def parseargs(self):
	parser = argparse.ArgumentParser(prog='ftpnumr8.py', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
        self.userList=args.userList
        self.passList=args.passList

    def nmap_nse(self, ip_address, port):
        print "  ACTION: Performing nmap FTP script scan for " + ip_address + ":" + port
        results = subprocess.check_output(['nmap', '-sV', '-Pn', '-p', port, '--script', 'ftp-*', '-oN', '%s/ftp/%s_ftp.nmap' % (ip_address, ip_address), ip_address])

    def bruteforce(self, ip_address, port, userList, passList):
        print "INFO: Performing hydra ftp scan against " + ip_address 
        hydraCmd = "hydra -L %s -P %s -f -o pillageResults/%s_ftphydra.txt -u %s -s %s ftp" % (userList, passList, ip_address, ip_address, port)
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid ftp credentials found: " + result 
        except:
            print "INFO: No valid ftp credentials found"

if __name__ == "__main__":
    ftp = ftpnumr8()
