#!/usr/bin/env python

import ftplib
import os

#------------constants------------------
sites=[]
sites.append(['your-server.com','user','password'])
selected_site_index=0
site= sites[selected_site_index]
sub_dir= '' # '/sub-directory

file_report= "report.txt"

#-end------------constants---------------

site_url= site[0]
site_user= site[1]
site_pass= site[2]
report= os.path.join(os.path.curdir , file_report)

ftp = ftplib.FTP(site_url)
ftp.login(site_user, site_pass)


def clear_file_report():
    if os.path.exists (report):
        print "Removing the old report file"
        os.remove(report)
    else:
        print "Creating a new report file"

    append("FILE LIST") 

def append(text, ):
    if os.path.exists (report):
        f = open(report, "a")
    else:
        f = open(report, "w")
    f.write ("%s\n"%text)
    f.close()

def process():
    clear_file_report()
    
    files = []

    try:
        files = ftp.nlst(sub_dir)
            
    except ftplib.error_perm, resp:
        if str(resp) == "550 No files found":
            append("")
        else:
            append(resp)
            
    for f in files:
        print "Writing:%s" % f
        append(f)

if __name__ == "__main__":
    process()
