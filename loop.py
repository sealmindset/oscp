#!/usr/bin/env python

import gzip
import subprocess
import os

def chkit(ipaddr):
	with open(os.devnull, "wb") as limbo:
		result = subprocess.Popen(["ping", "-c1", str(ipaddr)], stdout=limbo, stderr=limbo).wait()
		return result	

with gzip.open('/root/access_log.txt.gz','r') as f:
	mylst = []
	for line in f:
		item = line.split(' ')[0]
		if not item in mylst:
			if chkit(item):
				print item, "inactive"
			else:
				print item, "active"
			mylst.append(item)
