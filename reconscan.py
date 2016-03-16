#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import * 
import os
import sys
import time 
import nmap
import re
import reconf
from reconf import *
import time
from functools import wraps
 
def fn_timer(function):
    @wraps(function)
    def function_timer(*args, **kwargs):
        t0 = time.time()
        result = function(*args, **kwargs)
        t1 = time.time()
        print ("Total time running %s: %s seconds" %
               (function.func_name, str(t1-t0))
               )
        return result
    return function_timer

def chkfolders():
    dpths = [reconf.rootpth,reconf.labpath,reconf.rsltpth,reconf.exampth,reconf.nmappth]
    for dpth in dpths:
        if not os.path.exists(dpth):
                os.makedirs(dpth)

@fn_timer
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def TCPScan(ip_address):
   ip_address = ip_address.strip()
   TCPSCAN = "nmap -sV -vv -Pn -A -sC -sS -T4 -p- -oA '%s/%s' %s"  % (reconf.exampth, ip_address, ip_address)
   print "\033[1;33m[*]\033[0;m Running general TCP nmap scans for " + ip_address
   subprocess.check_output(TCPSCAN, shell=True)

def UDPScan(ip_address):
   ip_address = ip_address.strip()
   UDPSCAN = "nmap -sV -vv -Pn -A -sC -sU -T4 --top-ports 200 -oA '%s/%sU' %s" % (reconf.exampth, ip_address, ip_address)
   print "\033[1;33m[*]\033[0;m Running general UDP nmap scans for " + ip_address
   subprocess.check_output(UDPSCAN, shell=True)

def opnPORTS(ip_address):
   try:
        fnmap = "%s/%s.nmap" % (reconf.exampth, ip_address)
        print "\033[1;31m [!] \033[0;m Parsing %s for identifying open ports" % (fnmap)
        if os.path.isfile(fnmap):
                CATS = "cat %s | grep open | cut -d'/' -f1 | sort -h | tr '\n' ','" % (fnmap)
                results = subprocess.check_output(CATS, shell=True)
                results = results.rstrip(',')
        else:
                print "\033[1;38m [!] \033[0;m %s is missing.  Run nmap with the -oA option" % (fnmap)
        return results
   except:
        pass

def vulnCHK(ip_address):
   try:
        oprts = opnPORTS(ip_address)
        if not re.search('Warning', oprts):
                VCHK = "nmap -sV -vv -Pn -n -p %s --script vuln --script-args=unsafe=1 -oA '%s/%s_vuln' %s" % (oprts, reconf.exampth, ip_address, ip_address)
                print "[+] Executing - %s" % (VCHK)
        else:
                VCHK = "nmap -sV -vv -Pn -n --script vuln --script-args=unsafe=1 -oA '%s/%s_vuln' %s" % (reconf.exampth, ip_address, ip_address)
                print "[+] Executing - %s" % (VCHK)

        print "\033[1;33m[*]\033[0;m Running general vuln scans for " + ip_address
        subprocess.call(VCHK, shell=True)
   except:
        pass

def createList(ipadr):
   nm = nmap.PortScanner()
   args = "-sP -PS -n -oG %s " % (reconf.opth)
   nm.scan(ipadr,arguments=args)

   fo = open(reconf.olst,"w")
   with open(reconf.opth) as input:
        for line in input:
                line = line.split(" ")
                if re.match('[a-zA-Z]',line[1]) is None:
                        fo.write("%s\n" % (line[1]))
   fo.close()
   return

def vpnstatus():
        return int(os.popen('ifconfig tap0 | wc -l').read().split()[0])

# grab the discover scan results and start scanning up hosts
if __name__=='__main__': 
   # Check if VPN to the Offsec lab is up
   if not vpnstatus() > 1:
        print "You forgot to connect to the lab"
	sys.exit()

   # Make sure the folders exists
   chkfolders()
   
   # Create list of active IPs
   createList(reconf.iprange)

   print "Intel Gathering"
   f = open(reconf.olst, 'r') 
   for scanip in f:
       jobs = []
       p = multiprocessing.Process(target=TCPScan, args=(scanip,))
       jobs.append(p)
       p.start()
   f.close()

for j in jobs:
       j.join() 
