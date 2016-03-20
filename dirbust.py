#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import *
import os
import sys
import re
import reconf
from reconf import *
import time
from functools import wraps
import argparse
import ipaddr
import nmapxml
from nmapxml import *

parser = argparse.ArgumentParser(description='Run a short or verbose dirb scan', prefix_chars='-+/',)

parser.add_argument('-ip', action='store', required=True, help='IP Address to be assessed')
parser.add_argument('--filename', action='store', required=False, default='common.txt', help='Direct dirb to use this file')
parser.add_argument('-v', action='store_false', default=None, help='Less verbose')
parser.add_argument('+v', action='store_true', default=None, help='Verbose scan')

args = parser.parse_args()
try:
        ip_address = ipaddr.IPAddress(args.ip)
except:
        print "Try again..."
        sys.exit()

tfiles = len([name for name in os.listdir(reconf.wordlst) if os.path.isfile(os.path.join(reconf.wordlst, name))])

def hms(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return("%d:%02d:%02d" % (h, m, s))

def fn_timer(function):
    @wraps(function)
    def function_timer(*args, **kwargs):
        t0 = time.time()
        result = function(*args, **kwargs)
        t1 = time.time()
        print ("\033[0;30mTook %s \033[1;30m%s\033[0;m to complete\033[0;m" %
               (function.func_name, hms(t1-t0))
              )
        return result
    return function_timer

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def dirbEnum(prot, ip_address, port, igncap, srvr):
	found = []
	url = "%s://%s:%s" % (prot, ip_address, port)
	filename = args.filename 
	print "\033[0;33m[>]\033[0;m Running dirb scan for %s" % (url)
	outfile = "%s/%s_%s_dirb.txt" % (reconf.rsltpth, ip_address, port)
	if igncap == True:
		dirbargs = "-i -S -r -w"
	elif igncap == False:
		dirbargs = "-S -r -w"
	try:
		DIRBSCAN = "dirb %s %s/%s %s" % (url, reconf.wordlst, filename, dirbargs)
		results = subprocess.check_output(DIRBSCAN, shell=True)
		resultarr = results.split("\n")
		for line in resultarr:
			if re.match(r'\A[+]', line) or re.search(r'DIRECTORY', line):
				print "[+] Found -> %s" % (line)
				with open(outfile, 'a') as file:
					file.write("%s\n" % line) 
	except:
		pass

@fn_timer
def dirbBlast(prot, ip_address, port, igncap, srvr):
	found = []
	url = "%s://%s:%s" % (prot, ip_address, port)
	print "\033[0;33m[>]\033[0;m Running dirb scan for %s" % (url)
	outfile = "%s/%s_%s_dirb.txt" % (reconf.rsltpth, ip_address, port)
	extlst = "%s/%s" % (reconf.wordlst, 'extensions_common.txt')
	if igncap == True:
		dirbargs = "-i -f -S -w"
	elif igncap == True:
		dirbargs = "-f -S -w"
	 
	i = 1
	for filename in os.listdir(reconf.wordlst):
		fn = "%s/%s" % (reconf.wordlst, filename)
		if os.path.isfile(fn):
			print "\033[0;30m[ %s of %s ] Parsing thru %s/%s\033[0;m" % (i, tfiles, reconf.wordlst, filename)
		DIRBSCAN = "dirb %s %s/%s,%s/%s %s -x %s" % (url, reconf.wordlst, filename, reconf.vulns, srvr, dirbargs, extlst)
		print DIRBSCAN
		try:
			results = subprocess.check_output(DIRBSCAN, shell=True)
			resultarr = results.split("\n")
			for line in resultarr:
				if re.match(r'\A[+]', line) or re.search(r'DIRECTORY', line):
					print "[+] Found -> %s" % (line)
					with open(outfile, 'a') as file:
						file.write("%s\n" % line) 
			if os.path.isfile(fn): i += 1 
		except:
			pass 

def typeHDR(pattern):
        files = os.listdir(reconf.vulns)
        for file in files:
                if file.find(pattern) != -1:
                        return file

def vpnstatus():
   return int(os.popen('ifconfig tap0 | wc -l').read().split()[0])

if __name__=='__main__':
    # Check if VPN to the Offsec lab is up
    if not vpnstatus() > 1:
        print "You forgot to connect to the lab"
        sys.exit()

    xml_path = "%s/%s.xml" % (reconf.exampth, ip_address)
    info = minidom.parse(xml_path)
    opsys = nmapxml.get_OS(info)
    
    print "\033[1;33m[*]\033[0;m Operating System is %s" % (opsys)

    if re.search(r'Windows|Microsoft', opsys):
	igncap = True 
    else:
	igncap = False 

    print "\033[1;32m[*]\033[0;m Parsing %s/%s.nmap" % (reconf.exampth, ip_address)

    fnmap = "%s/%s.nmap" % (reconf.exampth, ip_address)
    with open(fnmap, 'r') as searchfile:
	for line in searchfile:
		if 'open' in line and re.search('http|ssl/http|https', line):
			port = re.split('\s+', line)[0]
			port = re.split('\/', port)[0].strip()
			prot = re.split('\s+', line)[2].strip()
			prot = re.split('\?', prot)[0].strip()
			if 'ssl/http' in line: prot = 'https'

			wbxml = "%s/%s_%s_httpheader.xml" % (reconf.exampth, ip_address, port)
			info = minidom.parse(wbxml)
			protocol, port_number, service, product, version = nmapxml.generic_Info(info)

			vulfiles = ['apache','cgis','domino','fatwire','hpsmh','iis','jboss','jrun','oracle','sap','sunas','tomcat','weblogic','axis','coldfusion','frontpage','hyperion','iplanet','jersey','netware','ror','sharepoing','test','vignette','websphere']
			for file in vulfiles:
				if re.search(file, product, re.IGNORECASE):
					srvr = typeHDR(file)
   
			if args.v is False: dirbEnum(prot, ip_address, port, igncap, srvr)
			if args.v is True: dirbBlast(prot, ip_address, port, igncap, srvr)
