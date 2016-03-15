#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import *
import os
import sys
import time
import re
import pip
installed_packages = pip.get_installed_distributions()
import reconf
from reconf import *

def chkfolders():
    dpths = [reconf.rootpth,reconf.labpath,reconf.rsltpth,reconf.exampth,reconf.nmappth]
    for dpth in dpths:
        if not os.path.exists(dpth):
		print "[!] $s folder is missingi, creating it now..." % (dpth)
                os.makedirs(dpth)
	else:
		print "[+] We're okay, %s folder exists" % (dpth)

def upnsedb(url):
	NSE = "wget -c %s -P %s" % (url, '/usr/share/nmap/scripts')
	print "[!] Fetching %s " % (nsefile)
	subprocess.call(NSE, shell=True)
	print "[+] Updating Nmap database with %s " % (nsefile)
	UPNSEDB = "nmap --script-updatedb"
	subprocess.call(UPNSEDB, shell=True)

def install(package):
	pip.main(['install', package])

if __name__=='__main__':
	print "[*] Installing missing NSE scripts..."
	nsearray = ['vulscan.nse','http-screenshot-html.nse','smb-check-vulns.nse']
	for nsefile in nsearray:
		nsescript = "/usr/share/nmap/scripts/%s" % (nsefile)
		if not os.path.isfile(nsescript):
			if re.search('vulscan.nse', nsefile):
				upnsedb('https://raw.githubusercontent.com/cldrn/nmap-nse-scripts/master/scripts/6.x/vulscan.nse')
			if re.search('http-screenshot-html.nse', nsefile):
				upnsedb('https://raw.githubusercontent.com/afxdub/http-screenshot-html/master/http-screenshot-html.nse')
			if re.search('smb-check-vulns.nse', nsefile):
				upnsedb('https://svn.nmap.org/nmap-exp/scriptsuggest/scripts/smb-check-vulns.nse')
		else:
			print "[+] %s is already installed" % (nsefile)

	FN = "wkhtmltoimage"
	TAR = "wkhtmltox-0.12.3_linux-generic-amd64.tar.xz"
	URL = "wget -c http://download.gna.org/wkhtmltopdf/0.12/0.12.3/%s" % (TAR) 
	EXT = "wkhtmltox/bin/%s" % (FN)
	BIN = "/usr/local/bin"
	BFN = "%s/%s" % (BIN, FN)
	TXZ = "tar -Jxf %s" % (TAR)	
	CXZ = "cp %s %s" % (EXT, BIN)	
	print "[*] Checking for the installation of %s..." % (FN)
	if not os.path.isfile(BFN):
		if not os.path.isfile(BFN):
			if not os.path.isfile(TAR):
				print "[+] Downloading wkhtmltoimage..."
				filename = subprocess.call(URL, shell=True)
			else:
				print "[+] Extracting %s file %s to %s..." % (TAR, EXT, BIN)
				subprocess.call(TXZ, shell=True)
				subprocess.call(CXZ, shell=True)
				if not os.path.isfile(BFN):
					print "[!] %s not found in %s" % (FN, BIN)
				else:
					print "[+] %s is install to %s" % (FN, BIN)
	else:
		print "[+] We're good: %s is installed" % (FN)

	print "[*] Checking for the necessary folders..."
	chkfolders()

	print "[*] Checking if the required modules are installed..."
	pkgs = ['xsser', 'python-libnmap', 'python-nmap']
	fipkgs = [package.project_name for package in installed_packages]
	for pkgname in pkgs:
		if pkgname in fipkgs:		
			print "[+] The %s module is installed..." % (pkgname)
		else:
			print "[!] The %s module hasn't been installed yet..." % (pkgname)
			print "[!] Installing %s module now..." % (pkgname)
			install(pkgname)
