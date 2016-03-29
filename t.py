#!/usr/bin/env python

import scapy
from scapy.all import *

output=sr(IP(dst='192.168.31.204')/ftp())
print "0: %s" % output
result, unan=output
print "R: %s" % result
