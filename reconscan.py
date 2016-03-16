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
import timeit

start_time = time.time()

def measureit(seconds):
   m, s = divmod(seconds, 60)
   h, m = divmod(m, 60)
   print "Execution time to completion: %d:%02d:%02d" % (h, m, s) 

def chkfolders():
    dpths = [reconf.rootpth,reconf.labpath,reconf.rsltpth,reconf.exampth,reconf.nmappth]
    for dpth in dpths:
        if not os.path.exists(dpth):
                os.makedirs(dpth)

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def TCPScan(ip_address):
   ip_address = ip_address.strip()
   TCPSCAN = "nmap -sV -vv -Pn -A -sC -sS -T4 -p- -oA '%s/%s' %s"  % (reconf.exampth, ip_address, ip_address)
   print "INFO: Running general TCP nmap scans for " + ip_address
   subprocess.check_output(TCPSCAN, shell=True)
   return

def UDPScan(ip_address):
   ip_address = ip_address.strip()
   #UDPSCAN = "nmap -sV -vv -Pn -A -sC -sU -T4 --top-ports 200 -oA '%s/%sU' %s" % (reconf.exampth, ip_address, ip_address)
   #print "INFO: Running general UDP nmap scans for " + ip_address
   #subprocess.check_output(UDPSCAN, shell=True)
   return

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
   start_time = time.time()
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

end_time = (time.time() - start_time)
measureit(end_time)

