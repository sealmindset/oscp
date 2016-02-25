#!/usr/bin/env python
import sys
import os

import nmap

try:
        nm = nmap.PortScanner()
except nmap.PortscannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(0)
except:
        print('Unexpected error:', sys.exc_info()[0])
        sys.exit(0)

ip = "10.4.1.0/24"
os.system("nmap -sP -n --unprivileged -oG iplist.gnmap "+ip+" --reason")
