#!/usr/bin/env python

import ftplib
import os

from ftplib import FTP

def get_dirs_ftp(folder=""):
    contents = ftp.nlst(folder)
    folders = []
    for item in contents:
        if "." not in item:
            folders.append(item)
    return folders

def get_all_dirs_ftp(folder=""):
    dirs = []
    new_dirs = []

    new_dirs = get_dirs_ftp(folder)

    while len(new_dirs) > 0:
        for dir in new_dirs:
            dirs.append(dir)

        old_dirs = new_dirs[:]
        new_dirs = []
        for dir in old_dirs:
            for new_dir in get_dirs_ftp(dir):
                new_dirs.append(new_dir)

    dirs.sort()
    return dirs


host ="your host"
user = "user"
password = "password"

print("Connecting to {}".format(host))
ftp = FTP(host)
ftp.login(user, password)
print("Connected to {}".format(host))
