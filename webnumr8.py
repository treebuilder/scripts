import argparse
import time
import sys
import os
import subprocess

class webnumr8(object):
    def __init__(self):
        self.parseargs()
        self.site="%s://%s:%s" % (self.protocol, self.host, self.port)
        self.nmap_nse(self.host, self.port)
        self.nikto(self.host, self.port)
        self.dirb(self.host, self.port)

    def parseargs(self):
        parser = argparse.ArgumentParser(prog='webnumr8.py', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
	parser.add_argument('protocol', help='web protocol')
        parser.add_argument('userlist', help='users to use in bruteforce')
        parser.add_argument('passlist', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
	self.protocol=args.protocol
        self.userlist=args.userlist
        self.passlist=args.passlist

    def nmap_nse(self, ip_address, port):
        print "  ACTION: Performing nmap web script scan for " + ip_address + ":" + port
        try:
          subprocess.check_output(['nmap', '-sV', '-Pn', '-p', port, '--script', 'http-enum,http-comments-displayer,http-dombased-xss,http-auth-finder,http-auth,http-internal-ip-disclosure,http-backup-finder,http-default-accounts,http-exif-spider,http-headers,http-ntlm-info,http-phpself-xss,http-rfi-spider,http-robots.txt,http-shellshock,http-sitemap-generator,http-sql-injection,http-userdir-enum,http-vhosts,http-waf-detect,http-waf-fingerprint', '-oN', '%s/http/%s_%s_%s.nmap' % (ip_address, ip_address, self.protocol, port), ip_address])
        except subprocess.CalledProcessError as grepexc: 
          print "nmap pooped.  error code", grepexc.returncode, grepexc.output

    def dirb(self, ip_address, port):
        print "  ACTION: Starting dirb scan for %s:%s " % (ip_address, port)
        filename="/usr/share/wordlists/dirb/common.txt"
        try:
          results = subprocess.check_output(['dirb', self.site, filename, '-S', '-w', '-o', '%s/http/%s_dirb_%s.txt' % (ip_address, ip_address, port)])
        except subprocess.CalledProcessError as grepexc: 
          print "dirb pooped.  error code", grepexc.returncode, grepexc.output


    def nikto(self, ip_address, port):
        print "  ACTION: Performing Nikto Scan on " + ip_address + ":" + port
        subprocess.check_output(['nikto', '-h', '%s://%s' % (self.protocol, ip_address), '-p', port, '-C', 'all', '-o', '%s/http/%s_%s_nikto_%s.txt' % (ip_address, ip_address, self.protocol, port)])

if __name__ == "__main__":
    web = webnumr8()
