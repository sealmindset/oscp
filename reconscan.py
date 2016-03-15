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

def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script         
       subprocess.call(SCRIPT, shell=True)
    return

def searchsploitEnum(ip_address):
    print "INFO: Searching for known exploits for " + ip_address
    SCRIPT = "./vulnrecon.py %s" % (ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCAN = "nmap -sV -Pn -n -vv -p %s --script=%s -oN %s/%s_http.nmap %s" % (port, reconf.nmapscripts, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    #DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    #subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCANS = "nmap -sV -Pn -n -vv -p %s --script=%s -oX %s/%s_https.nmap %s" % (port, reconf.nmapscripts, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    #DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    #subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def oracleEnum(ip_address, port):
    print "INFO: Detected Oracle on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    ORACLESCAN = "nmap -vv -sV -Pn -p %s --script=oracle-enum-users,oracle-sid-brute -oX %s/%s_oracle.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(ORACLESCAN, shell=True)

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX %s/%s_mssql.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def mysqlEnum(ip_address, port):
    print "INFO: Detected MySQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oX %s/%s_mysql.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(MYSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on " + ip_address + ":" + port
    SCRIPT = "./snmprecon.py %s" % (ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" % (ip_address)       
       subprocess.call(SCRIPT, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)" 
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
    return

def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on " + ip_address + ":" + port
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
    return

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   serv_dict = {}
   TCPSCAN = "nmap -sV -vv -Pn -A -sC -sS -T 4 -p- -oN '%s/%s.nmap' -oX '%s/%s_nmap_scan_import.xml' %s"  % (reconf.exampth, ip_address, reconf.nmappth, ip_address, ip_address)
   UDPSCAN = "nmap -sV -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/%sU.nmap' -oX '%s/%sU_nmap_scan_import.xml' %s" % (reconf.exampth, ip_address, reconf.nmappth, ip_address, ip_address)
   print "INFO: Running general TCP nmap scans for " + ip_address
   results = subprocess.check_output(TCPSCAN, shell=True)
   print "INFO: Running general UDP nmap scans for " + ip_address
   udpresults = subprocess.check_output(UDPSCAN, shell=True)
   lines = results.split("\n")
   for line in lines:
      ports = []
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
	 while "  " in line: 
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
	 port = line.split(" ")[0] # grab the port/proto
         if service in serv_dict:
	    ports = serv_dict[service] # if the service is already in the dict, grab the port list
	 
         ports.append(port) 
	 serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
   
   # go through the service dictionary to call additional targeted enumeration functions 
   for serv in serv_dict: 
      ports = serv_dict[serv]	
      if (serv == "http"):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)
      elif (serv == "ssl/http") or ("https" in serv):
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpsEnum, ip_address, port)
      elif "ssh" in serv:
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(sshEnum, ip_address, port)
      elif "smtp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smtpEnum, ip_address, port)
      elif "snmp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(snmpEnum, ip_address, port)
      elif ("domain" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(dnsEnum, ip_address, port)
      elif ("ftp" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(ftpEnum, ip_address, port)
      elif "microsoft-ds" in serv:	
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smbEnum, ip_address, port)
      elif "ms-sql" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(mssqlEnum, ip_address, port)
      elif "oracle-tns" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(oracleEnum, ip_address, port)
      elif "mysql" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(mysqlEnum, ip_address, port)
      
   print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
   searchsploitEnum(ip_address)
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
       p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       jobs.append(p)
       p.start()
   f.close()

for j in jobs:
	j.join() 
