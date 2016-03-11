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

if len(sys.argv) != 2:
    print "Usage: vulnrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1].strip()

def test_patterns(text, patterns=[]):
    # Look for each pattern in the text and print the results
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            s = match.start()
            e = match.end()
    	    return (int(s), int(e))

def prodreplace(text):
    tags = ['windows','xp','98','2000','enterprise edition','http server powered by','transaction coordinator','for','httpd','listener','service','release']
    for tag in tags:
	if tag in text:
		return (text.replace(tag, ''))

def osreplace(text):
    tags = ['windows','enterprise edition release']
    for tag in tags:
	if tag in text:
		return (text.replace(tag, ''))

def ssploit(prod,ver,os):
	if re.search('rdp',prod):
		if re.search('windows',os):
			SPLOIT = "searchsploit %s %s" % (prod,os)
	else:
		SPLOIT = "searchsploit %s %s" % (prod,ver)
	APLOIT = "%s|%s" % (prod,ver)
	OPLOIT = "searchsploit %s %s" % (prod,os)
	AOLOIT = "%s|%s" % (prod,os)
	try:
    		results = subprocess.check_output(SPLOIT, shell=True)
		if re.search(APLOIT, results):
            		return results
		else:
    			results = subprocess.check_output(OPLOIT, shell=True)
			if re.search(AOLOIT, results):
				return results
	except:
    		print "INFO: No exploits found for %s %s" % (prod, ver) 


xmlfile = "%s/%s_nmap_scan_import.xml" % (reconf.nmappth, ip_address)
with open (xmlfile, 'rt') as file: 
    tree = ElementTree.parse(file)

rep = NmapParser.parse_fromfile(xmlfile) 
for _host in rep.hosts:
	host = ', '.join(_host.hostnames)

if  _host.os.osmatches:
        for osmatch in _host.os.osmatches:
                os = osmatch.name
else:
        os = "unknown" 

if re.match('Microsoft|Windows', os):
    for services in _host.services: 
	prod = ''
	ver = ''
	os = ''
	serv = services.banner
	#print
     	#print "Pre - Port: "'{0: <5}'.format(services.port), "Serv: "'{0: <34}'.format(serv) 
	serv = serv.replace('Microsoft ', '')
	if serv:
		if 'product' in serv and 'version' in serv and 'ostype' in serv and 'extrainfo' in serv:
			sp, pe = test_patterns(serv, ['product:'])		
			sv, ve = test_patterns(serv, ['version:'])		
			so, oe = test_patterns(serv, ['ostype:'])		
			se, ee = test_patterns(serv, ['extrainfo:'])		
			prod = serv[pe:(sv-1)].strip().lower()
			ver = serv[ve:(se-1)].strip().lower()
			ex = serv[ee:se-1].strip().lower()
			os = serv[oe:].strip().lower()
			if services.port == 443:
				prod = "https"
				os = "windows"
			if re.search('microsoft-ds', prod) and services.port == 445:
				prod = "smb"
			if re.search('netbios-ssn', prod) and services.port == 139:
				prod = "netbios"
			if re.search('tns', prod) and services.port == 1521 or services.port == 1526:
				prod = "tns"
			if re.search('apache', prod) and services.port == 7777 or services.port == 7778:
				prod = "apache"
			if re.search('terminal', prod) and services.port == 3389:
				prod = "rdp"
			if len(prod.split()) > 1:
				prod = prodreplace(prod).strip()
			if len(ver.split('.')) > 2:
				i = iter(ver.split('.'))
				ver = map('.'.join,zip(i,i))[0] 
			if len(os.split()) > 1:
				i = iter(os.split())
				os = map(''.join,zip(i,i))[0] 
				os = osreplace(os).strip()
		if 'product' in serv and 'version' in serv and 'ostype' in serv and not 'extrainfo' in serv:
			sp, pe = test_patterns(serv, ['product:'])		
			sv, ve = test_patterns(serv, ['version:'])		
			so, oe = test_patterns(serv, ['ostype:'])		
			prod = serv[pe:(sv-1)].strip().lower()
			ver = serv[ve:(so-1)].strip().lower()
			os = serv[oe:].strip().lower()
                        if services.port == 443:
                                prod = "https"
                                os = "windows"
			if re.search('microsoft-ds', prod) and services.port == 445:
				prod = "smb"
			if re.search('netbios-ssn', prod) and services.port == 139:
				prod = "netbios"
			if re.search('tns', prod) and services.port == 1521 or services.port == 1526:
				prod = "tns"
			if re.search('terminal', prod) and services.port == 3389:
				prod = "rdp"
			if len(prod.split()) > 1:
				prod = prodreplace(prod).strip()
			if len(ver.split('.')) > 2:
				i = iter(ver.split('.'))
				ver = map('.'.join,zip(i,i))[0] 
			if len(os.split()) > 1:
				os = osreplace(os).strip()
		if 'product' in serv and 'ostype' in serv and not 'version' in serv and not 'extrainfo' in serv:
			sp, pe = test_patterns(serv, ['product:'])		
			so, oe = test_patterns(serv, ['ostype:'])		
			prod = serv[pe:(so-1)].strip().lower()
			os = serv[oe:].strip().lower()
                        if services.port == 443:
                                prod = "https"
                                os = "windows"
			if re.search('microsoft-ds', prod) and services.port == 445:
				prod = "smb"
			if re.search('netbios-ssn', prod) and services.port == 139:
				prod = "netbios"
			if re.search('tns', prod) and services.port == 1521 or services.port == 1526:
				prod = "tns"
			if re.search('terminal', prod) and services.port == 3389:
				prod = "rdp"
			if len(prod.split()) > 1:
				prod = prodreplace(prod).strip()
			if len(os.split()) > 1:
				os = osreplace(os).strip()
			ver = "" 
		if 'product' in serv and 'version' in serv and 'extrainfo' in serv and not 'ostype' in serv:
			sp, pe = test_patterns(serv, ['product:'])		
			sv, ve = test_patterns(serv, ['version:'])		
			se, ee = test_patterns(serv, ['extrainfo:'])		
			prod = serv[pe:(sv-1)].strip().lower()
			ver = serv[ve:(se-1)].strip().lower()
			ex = serv[ee:].strip().lower()
			if re.search('microsoft-ds', prod) and services.port == 445:
				prod = "smb"
			if re.search('netbios-ssn', prod) and services.port == 139:
				prod = "netbios"
			if re.search('tns', prod) and services.port == 1521 or services.port == 1526:
				prod = "tns"
			if re.search('terminal', prod) and services.port == 3389:
				prod = "rdp"
			if re.search('oracle', ex):
				prod = prodreplace(ex).strip()
			if len(prod.split()) > 1:
				prod = prodreplace(prod).strip()
			if len(ver.split('.')) > 2:
				i = iter(ver.split('.'))
				ver = map('.'.join,zip(i,i))[0] 
			os = "windows"
                if 'product' in serv and 'version' in serv and 'hostname' in serv:
                        sp, pe = test_patterns(serv, ['product:'])
                        sv, ve = test_patterns(serv, ['version:'])
                        so, oe = test_patterns(serv, ['hostname:'])
                        prod = serv[pe:(sv-1)].strip().lower()
                        ver = serv[ve:(so-1)].strip().lower()
                        os = serv[oe:].strip().lower()
                        if services.port == 443:
                                prod = "https"
                                os = "windows"
                        if re.search('microsoft-ds', prod) and services.port == 445:
                                prod = "smb"
                        if re.search('netbios-ssn', prod) and services.port == 139:
                                prod = "netbios"
                        if re.search('tns', prod) and services.port == 1521 or services.port == 1526:
                                prod = "tns"
                        if re.search('ftpd', prod) and services.port == 2100:
                                prod = "ftp"
			if re.search('terminal', prod) and services.port == 3389:
				prod = "rdp"
                        if len(prod.split()) > 1:
                                prod = prodreplace(prod).strip()
                        if len(ver.split('.')) > 2:
                                i = iter(ver.split('.'))
                                ver = map('.'.join,zip(i,i))[0]
                        if len(os.split()) > 1:
                                i = iter(os.split())
                                os = map(''.join,zip(i,i))[0]
                                os = osreplace(os).strip()
	else:
        	if services.port == 443:
                	prod = "https"
                        os = "windows"
		else:	
			prod = ""
			ver = ""
			os = "windows"
     	
	print "INFO: Performing searchsploit on Port: "'{0: <5}'.format(services.port), "Prod: "'{0: <15}'.format(prod), "Version: "'{0: <15}'.format(ver), "OS: "'{0: <15}'.format(os) 

	if os and prod or ver: 
		result = ssploit(prod, ver, os)
		ofile = "%s/%s_exploitdb.txt" % (reconf.exampth,ip_address)
		rhead = "\n IP Address: %s Port: %s \n" % (ip_address,services.port)		
		try:
			with open(ofile, 'a') as file:
				file.write(rhead)
				file.write(result) 		
		except:
			print "ERROR: Couldn't write to %s" % (ofile)		
