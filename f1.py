#!/usr/bin/env python

import ftplib
import os

import ftputil.ftp_error.PermanentError as PermanentError

ftp = ftputil.FTPHost('ftp.site.com','user','pass')
try:
    recursive = ftp.walk("/path/dir1",topdown=True,onerror=None)
    for root,dirs,files in recursive:
         for name in files:
              print name
except PermanentError e:
   print "Permanent Error: %s occurred" % (e)
ftp.close
