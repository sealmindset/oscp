#!/usr/bin/env python

import ConfigParser

def set_vars():
    global iprange
    global rootpth
    global labpath
    global rsltpth
    global exampth
    global nmappth
    global httpnse
    global wordlst
    global vulns
    global usrlst
    global pwdlst
    global fzzlst
    global opth
    global olst
    global nsepth

    config = ConfigParser.ConfigParser()
    config.read('recon.conf')

    iprange = config.get('hosts','iprange')
    opth = config.get('hosts','opth')
    olst = config.get('hosts','olst')

    rootpth = config.get('base','rootpth')
    labpath = config.get('base','labpath')

    basepth = config.get('paths','basepth')
    rsltpth = config.get('paths','rsltpth')
    exampth = config.get('paths','exampth')
    nmappth = config.get('paths','nmappth')
    wordlst = config.get('wordlist','wordlst')
    vulns = config.get('vuln','vulns')

    httpnse = config.get('nmapscripts','httpnse')
    nsepth = config.get('nmapscripts','nsepth')

    usrlst = config.get('crack','usrlst')
    pwdlst = config.get('crack','pwdlst')
    fzzlst = config.get('crack','fzzlst')

set_vars()
