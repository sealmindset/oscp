#!/bin/sh
# In the lab the iface should be tap0

iface=$1
ipadd=$2
range=$3
wksp=$4

nmap --iflist -oN nmap_iflist

netdiscover -r ${range} -i ${iface}

unicornscan -i ${iface} -I -mT ${ipadd}:a
unicornscan -i ${iface} -I -mU ${ipadd}:a

nmap -Pn -n -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oX ${wksp}/nmap_qt ${ipadd}
nmap -Pn -n --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T3 -oX ${wksp}/nmap_qu ${ipadd}

ports=$(cat ${wksp}/nmap_qt | grep portid | grep protocol=\"tcp\" | cut -d'"' -f4 | paste -sd ",")
nmap -nvv -Pn -n -sSV -T1 -p${ports} --version-intensity 9 -A -oA nmap_ft ${ipadd}

nmap -e ${iface} -n -v -Pn -sV -sC -p${ports} --version-light -A -sS -oN ${wksp}/nmap_lt ${ipadd}
nmap -e ${iface} -n -v -Pn -sV -sC --version-light -A -sU -oN ${wksp}/nmap_lu ${ipadd}

#if Port 135 - RPC
nmap -v -p 139,445 --script=rpc-check-vulns -oN ${wksp}/nmap_smb ${ipadd}

#If Port 139/445
nmap -v -p 139,445 --script=smb-check-vulns -oN ${wksp}/nmap_smb ${ipadd}
enum4linux -v -a ${ipadd} >> ${wksp}/e4l_smb

#If Port 80/443
nmap --script http-enum -oN ${wksp}/nmap_http ${ipadd}

curl -i ${ipadd}/robots.txt >> ${wksp}/curl_robots

nikto -output ${wksp}/nikto -host ${ipadd}

gobuster -u http://${ipadd} -w /root/wordlist/RobotDisallowed/Top1000-RobotsDisallowed.txt
gobuster -u http://${ipadd} -w /root/wordlist/SecLists/Discovery/Web_Content/common.txt
