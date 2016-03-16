#!/usr/bin/env python
from xml.etree import ElementTree
from libnmap.parser import NmapParser
import subprocess
from subprocess import *
import sys
import os
import re
import reconf
from reconf import *
import time
from functools import wraps

if len(sys.argv) != 2:
    print "Usage: deeprecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1].strip()

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

def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on %s %s" % (ip_address, port)
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script     
       subprocess.call(SCRIPT, shell=True)
    return

def searchsploitEnum(ip_address):
    print "INFO: Searching for known exploits for %s" % (ip_address)
    SCRIPT = "./vulnrecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap web script scan for %s:%s" % (ip_address, port) 
    HTTPSCAN = "nmap -sV -Pn -n -vv -p %s --script=%s -oN %s/%s_http.nmap %s" % (port, reconf.httpnse, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    #DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    #subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap web script scan for %s:%s" % (ip_address, port) 
    HTTPSCANS = "nmap -sV -Pn -n -vv -p %s --script=%s -oX %s/%s_https.nmap %s" % (port, reconf.httpnse, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    #DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    #subprocess.call(DIRBUST, shell=True)
    #NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def oracleEnum(ip_address, port):
    print "INFO: Detected Oracle on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap mssql script scan for %s:%s" % (ip_address, port)
    ORACLESCAN = "nmap -vv -sV -Pn -p %s --script=oracle-enum-users,oracle-sid-brute -oX %s/%s_oracle.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(ORACLESCAN, shell=True)

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap mssql script scan for %s:%s" % (ip_address, port)
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX %s/%s_mssql.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def mysqlEnum(ip_address, port):
    print "INFO: Detected MySQL on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap mssql script scan for %s:%s" % (ip_address, port)
    MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oX %s/%s_mysql.xml %s" % (port, reconf.exampth, ip_address, ip_address)
    results = subprocess.check_output(MYSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on %s:%s" % (ip_address, port)
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on %s:%s" % (ip_address, port)
    SCRIPT = "./snmprecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on %s:%s" % (ip_address, port)
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on %s:%s" % (ip_address, port)
    SCRIPT = "./smbrecon.py %s" % (ip_address)
    subprocess.call(SCRIPT, shell=True)
    return

def tbdEnum(tbd):
    print "\033[1;31m[!]\033[1;m To be developed: %s" % (tbd) 
    return

def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on %s:%s" % (ip_address, port)
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def altOSEnum(ip_address):
    print "INFO: Alternative OS detection for %s" % (ip_address)
    OSTRY = "nmap -O --osscan-guess %s" % (ip_address)
    results = subprocess.check_output(OSTRY, shell=True)
    rsltarray = results.split('\n')
    for line in rsltarray:
        if re.search('Running',line):
                if re.search('GUESSING',line):
                        os = line.split(':')[1].strip()
                else:
                        os = line.split(':')[1].strip()
    return os

if __name__=='__main__':

    xmlfile = "%s/%s.xml" % (reconf.exampth, ip_address)
    with open (xmlfile, 'rt') as file: 
    	tree = ElementTree.parse(file)

    rep = NmapParser.parse_fromfile(xmlfile)
    for _host in rep.hosts:
    	host = ', '.join(_host.hostnames)
    	ip = (_host.address)

    serv = []
    for attb in tree.iter('service'): 
 	#print attb.attrib
    	name = attb.attrib.get('name')
	serv.append(name)

    try: 
    	for osmatch in _host.os.osmatches:
    		os = osmatch.name
    except IOError:	
	os = 'Microsoft'
    else:
	os = altOSEnum(ip_address)

    print "OS: %s" % (os)

    if 'Microsoft' in os:
	cnt=0
    	for services in _host.services:
		print
        	print "\033[1;33m[+]\033[1;m Port: "'{0: <5}'.format(services.port), "Service: "'{0: <10}'.format(serv[cnt])
		print 
		# 21
		if re.search('ftp', serv[cnt]):
			print "[+] Running ftpEnum %s, %s" % (ip_address, services.port)
			ftpEnum(ip_address, services.port)
		# 22
		if re.search('ssh',serv[cnt]):
			print "[+] Running sshEnum %s, %s" % (ip_address, services.port)
			sshEnum(ip_address, services.port)
		# 25
		if re.search('smtp',serv[cnt]):
			print "[+] Running smtpEnum %s, %s" % (ip_address, services.port)
			smtpEnum(ip_address, services.port)
		# 53
		if re.search('domain',serv[cnt]):
			print "[+] Running dnsEnum %s, %s" % (ip_address, services.port)
			dnsEnum(ip_address, services.port)
		# 80
		if not re.search('https',serv[cnt]) and re.search('http',serv[cnt]):
			print "[+] Running httpEnum %s, %s" % (ip_address, services.port)
			httpEnum(ip_address, services.port)
		# 135
		if re.search('msrpc', serv[cnt]):
			print "[+] Running rpcEnum %s, %s" % (ip_address, services.port)
			tbdEnum(serv[cnt])
		# 139
		if re.search('netbios-ssn', serv[cnt]):
			print "[+] Running rpcEnum %s, %s" % (ip_address, services.port)
			tbdEnum(serv[cnt])
		# 161-162
		if re.search('snmp',serv[cnt]):
			print "[+] Running snmpEnum %s, %s" % (ip_address, services.port)
			snmpEnum(ip_address, services.port)
		# 443
		if re.search('https',serv[cnt]):
			print "[+] Running httpsEnum %s, %s" % (ip_address, services.port)
			httpsEnum(ip_address, services.port)
		# 445
		if re.search('microsoft-ds', serv[cnt]):
			print "[+] Running smbEnum %s, %s" % (ip_address, services.port)
			smbEnum(ip_address, services.port)
		# 1433-1434
		if re.search('ms-sql', serv[cnt]):
			print "[+] Running mssqlEnum %s, %s" % (ip_address, services.port)
			mssqlEnum(ip_address, services.port)
		# 1521
		if re.search('oracle', serv[cnt]):
			print "[+] Running oracleEnum %s, %s" % (ip_address, services.port)
			oracleEnum(ip_address, services.port)
		# 3306
		if re.search('mysql', serv[cnt]):
			print "[+] Running mysqlEnum %s, %s" % (ip_address, services.port)
			mysqlEnum(ip_address, services.port)
		cnt += 1
   	print "[+] Running searchsploitEnum %s" % (ip_address)
   	searchsploitEnum(ip_address)
	print
   	print "INFO: Deep scan completed for " + ip_address
	cnt
    else:
	print "OS Unknown: %s" % (os)
 
if 'Linux' in os:
    cnt = 0
    for services in _host.services: 
        print "Port: "'{0: <5}'.format(services.port), "State: "'{0: <5}'.format(services.state), "Protocol: "'{0: <2}'.format(services.protocol),"Product: "'{0: <15}'.format(list_product[cnt]),"Version: "'{0: <10}'.format(list_version[cnt]),"ExtrInfo: "'{0: <10}'.format(list_extrainf[cnt])
        cnt = cnt + 1
