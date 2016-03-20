#!/usr/bin/env python
import subprocess
from subprocess import *
import sys
import os
import re
import reconf
from reconf import *
import argparse
import ipaddr
import nmapxml
from nmapxml import *
import fnmatch

def typeHDR(pattern):
	files = os.listdir(reconf.vulns)
	for file in files:
		if file.find(pattern) != -1:
			return file


port = "80"
ip_address = "192.168.31.205"

wbxml = "%s/%s_%s_httpheader.xml" % (reconf.exampth, ip_address, port)
info = minidom.parse(wbxml)
protocol, port_number, service, product, version = nmapxml.generic_Info(info)

vulfiles = ['apache','cgis','domino','fatwire','hpsmh','iis','jboss','jrun','oracle','sap','sunas','tomcat','weblogic','axis','coldfusion','frontpage','hyperion','iplanet','jersey','netware','ror','sharepoing','test','vignette','websphere']

for file in vulfiles:
	if re.search(file, product, re.IGNORECASE):
		srvr = typeHDR(file)

print srvr
