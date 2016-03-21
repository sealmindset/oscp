#!/usr/bin/env python
import subprocess
import sys
import reconf
from reconf import *
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname         
host = subprocess.check_output(HOSTNAME, shell=True).strip()
print "INFO: Attempting Domain Transfer on " + host
ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
ztresults = subprocess.check_output(ZT, shell=True)
if "failed" in ztresults:
    print "INFO: Zone Transfer failed for " + host
else:
    print "[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
    #outfile = exampth + "/" + ip_address + "_zonetransfer.txt"
    outfile = "%s/%s_zonetransfer.txt" % (reconf.exampth, ip_address)
    dnsf = open(outfile, "w")
    dnsf.write(ztresults)
    dnsf.close



# get nameservers for target domain
response = dns.resolver.query('example.com.',dns.rdatatype.NS)

# we'll use the first nameserver in this example
nsname = response.rrset[0] # name
response = dns.resolver.query(nsname,dns.rdatatype.A)
nsaddr = response.rrset[0].to_text() # IPv4

# get DNSKEY for zone
request = dns.message.make_query('example.com.',
                                 dns.rdatatype.DNSKEY,
                                 want_dnssec=True)

# send the query
response = dns.query.udp(request,nsaddr)
if response.rcode() != 0:
    # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

# answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
answer = response.answer
if len(answer) != 2:
    # SOMETHING WENT WRONG

# the DNSKEY should be self signed, validate it
name = dns.name.from_text('example.com.')
try:
    dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
except dns.dnssec.ValidationFailure:
    # BE SUSPICIOUS
else:
    # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com
