#!/usr/bin/env python

import os
import reconf
from reconf import *

def vpnstatus():
	return int(os.popen('ifconfig tap0 | wc -l').read().split()[0])

if vpnstatus > 1:
	print "Up"
else:
	print "Down"
