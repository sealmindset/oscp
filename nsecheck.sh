#!/bin/bash


declare -a nmapNSE=('http-vhosts.nse'
                    'http-userdir-enum.nse'
                    'http-apache-negotiation.nse'
                    'http-backup-finder.nse'
                    'http-config-backup.nse'
                    'http-default-accounts.nse'
                    'http-email-harvest.nse'
                    'http-methods.nse'
                    'http-method-tamper.nse'
                    'http-passwd.nse'
                    'http-robots.txt.nse'
                    'ms-sql-info.nse'
                    'ms-sql-config.nse'
                    'ms-sql-dump-hashes.nse'
                    'snmp-netstat.nse'
                    'snmp-processes.nse'
                    'ftp-anon.nse'
                    'ftp-bounce.nse'
                    'ftp-libopie.nse'
                    'ftp-proftpd-backdoor.nse'
                    'ftp-vsftpd-backdoor.nse'
                    'ftp-vuln-cve2010-4221.nse');

for ((i=0; i<${#nmapNSE[@]}; i++)); do
    nmapNSEVar=${nmapNSE[$i]}
    if [ ! -f /usr/share/nmap/scripts/$nmapNSEVar ]; then
        echo "$nmapNSEVar is missing"
    fi
done
