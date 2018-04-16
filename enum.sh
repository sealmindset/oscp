#!/bin/sh
#
iface=$1
ipadd=$2
range=$3
wks=$4

# In the lab the iface should be tap0
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

wkip="IP$(echo ${ipadd} | tr -d '.')"
wksp="${wks}/${wkip}"

#nmap --iflist -oN nmap_iflist
#netdiscover -r ${range} -i ${iface}
#unicornscan -i ${iface} -I -mT ${ipadd}:a
#unicornscan -i ${iface} -I -mU ${ipadd}:a

if [ -d $wksp ]; then
  echo "${GREEN} [*] ${NC} Workspace ${wksp} is ready."
else
  echo "${YELOW} [!] ${NC} Workspace ${wksp} is being setup."
  mkdir ${wksp}
fi

echo "${RED} [!!!] ${NC} Starting enumeration against ${ipadd}"

if [ ! -f ${wksp}/nmap_qt ]; then
  # Quick Scans
  echo "${GREEN} [*] ${NC} TCP Quick Scans."
  nmap -Pn -n -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oX ${wksp}/nmap_qt ${ipadd}
  echo "${GREEN} [*] ${NC} UDP Quick Scans."
  nmap -Pn -n --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T3 -oX ${wksp}/nmap_qu ${ipadd}
fi

# Get the open TCP Ports from Quick Scans (nmap_qt)
ports=$(cat ${wksp}/nmap_qt | grep portid | grep protocol=\"tcp\" | cut -d'"' -f4 | paste -sd ",")
echo "${YELLOW} [!] ${NC} The following TCP Ports are open: ${WHITE} ${ports}"

# Guess versions full
if [ ! -f ${wksp}/nmap_ft.xml ]; then
  echo "${GREEN} [*] ${NC} Identifying protocol versions of each port."
  #nmap -Pn -n -sSV -T1 -p${ports} --version-intensity 9 -A -oA ${wksp}/nmap_ft ${ipadd}
fi

# Guess versions light
if [ ! -f ${wksp}/nmap_lt ]; then
  echo "${GREEN} [*] ${NC} Identifying protocol versions of each TCP port (Light)."
  #nmap ${iface} -n -Pn -sV -sC --open -p${ports} --version-light -A -sS -oN ${wksp}/nmap_lt ${ipadd}
  echo "${GREEN} [*] ${NC} Identifying protocol versions of each UDP port (Light)."
  #nmap ${iface} -n -Pn -sV -sC --version-light -A -sU -oN ${wksp}/nmap_lu ${ipadd}
fi

# Run specialized scans
for port in $(echo $ports | sed "s/,/ /g"); do 
  echo "${GREEN} [*] ${NC} Checking for anything interesting on ${port}."
  if [ $port -eq 22 ]; then
    nmap -n -Pn -p ssh -sV -A -oN ${wksp}/nmap_ssh ${ipadd}
  fi
  if [ $port -eq 80 ] || [ $port -eq 443 ]; then
    nmap -n -Pn --script http-enum -oN ${wksp}/nmap_${port} ${ipadd}

    curl -i http://${ipadd}:${port}/robots.txt >> ${wksp}/curl_robots_${port}

    nikto -output ${wksp}/niktoi_${port} -host ${ipadd}
    if [ $port -eq 80 ]; then
      dirb http://${ipadd} -o ${wksp}/dirb_${port}
    else
      dirb https://${ipadd} -o ${wksp}/dirb_${port}
    fi
  fi
  if [ $port -eq 111 ]; then
    nmap -n -Pn -p 111 -sV -A -oN ${wksp}/nmap_${port} ${ipadd}
  fi
  if [ $port -eq 135 ]; then
    nmap -n -Pn -p 135 -A -oN ${wksp}/nmap_${port} ${ipadd}
  fi
  if [ $port -eq 139 ] || [ $port -eq 445 ]; then
    nmap -n -Pn -p $port -A -oN ${wksp}/nmap_${port} ${ipadd}
    enum4linux -v -a ${ipadd} >> ${wksp}/e4l_${port}
    smbclient -N --list=${ipadd} >> ${wksp}/smb_${port}
  fi
  if [ $port -eq 3306 ]; then
    nmap -n -Pn -p 3306 --script=mysql-enum -oN ${wksp}/nmap_${port} ${ipadd}
  fi
done
