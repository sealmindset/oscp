#!/bin/bash

SPEED=
ENUM=
PORTS=
XPLOIT=
TARGET=

while getopts ":s:e:p:x:t:" OPTIONS
do
            case $OPTIONS in
            s)     SPEED=$OPTARG;;
            e)     ENUM=$OPTARG;;
            p)     PORTS=$OPTARG;;
            x)     XPLOIT=$OPTARG;;
            t)     TARGET=$OPTARG;;
            ?)     printf "Invalid option: -$OPTARG\n" $0
                          exit 2;;
           esac
done

SPEED=${SPEED:=NULL}
ENUM=${ENUM:=NULL}
PORTS=${PORTS:=NULL}
XPLOIT=${XPLOIT:=NULL}
TARGET=${TARGET:=NULL}

##########################################
#  ~~~ Cleanup routine just in case ~~~  #
##########################################

rm /tmp/TCP_Ports.txt &>/dev/null
rm /tmp/UDP_Ports.txt &>/dev/null
rm /tmp/amap_list.txt &>/dev/null
rm /tmp/nmap_list.txt &>/dev/null
rm /tmp/search.txt &>/dev/null

##################
#  ~~~ Menu ~~~  #
##################

if [ $SPEED = NULL ] || [ $ENUM = NULL ] || [ $PORTS = NULL ] || [ $TARGET = NULL ] || [ $XPLOIT = NULL ]; then

echo "--------------------------------------------------------------------"
echo "|                          Fl@sh v1.6 ~ b33f                       |"
echo "|                    -Scanned Before you know it-                  |"
echo "--------------------------------------------------------------------"
echo "| USAGE: ./flash.sh -s [pps] -e [N/A/B] -p [A/D] -x [Y/N] -t [IP]  |"
echo "|                                                                  |"
echo "| REQUIRED                                                         |"
echo "|         -s  Packets per second [recommended less than 400].      |"
echo "|         -e  Pipe output into N (nmap), A (amap), B (both).       |"
echo "|         -p  A (full 65k), D (default port list).                 |"
echo "|         -x  Parse keywords in searchsploit (Y/N).                |"
echo "|         -t  Target IP.                                           |"
echo "|                                                                  |"
echo "| DETAILS                                                          |"
echo "|         (1) When the open ports are passed to nmap or amap       |"
echo "|         or both, the results will be saved to nmap-output.txt    |"
echo "|         and/or amap-output.txt in the parent directory...        |"
echo "|                                                                  |"
echo "|         (2) When using the -x you should bear in mind that you   |"
echo "|         you should update the the local version of exploit-db    |"
echo "|         browse to '/pentest/exploits/exploitdb/platforms' and    |"
echo "|         issue 'svn up'...                                        |"
echo "--------------------------------------------------------------------"

######################
#  ~~~ Scanning ~~~  #
######################

##########################
# unicornscan full range #
##########################
elif [ $PORTS = A ]; then

echo ""
echo "[*] Scanning Full TCP port range, be patient..."
unicornscan -mT -R2 -p1-65535 -r $SPEED $TARGET &>/dev/null >> /tmp/TCP_Ports.txt &wait
echo "[>] TCP Ports:"
cat /tmp/TCP_Ports.txt

echo ""
echo "[*] Scanning Full UDP port range, be patient..."
unicornscan -mU -R2 -p1-65535 -r $SPEED $TARGET &>/dev/null >> /tmp/UDP_Ports.txt &wait
echo "[>] UDP Ports:"
cat /tmp/UDP_Ports.txt

####################################
# Prepping output for amap && nmap #
####################################

########
# amap #
########

cat /tmp/TCP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' >> /tmp/amap_list.txt
cat /tmp/UDP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' >> /tmp/amap_list.txt

########
# nmap #
########

cat /tmp/TCP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' |sed 's/$/,/' |tr -d '\n' >> /tmp/nmap_list.txt
cat /tmp/UDP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' |sed 's/$/,/' |tr -d '\n' >> /tmp/nmap_list.txt

rm /tmp/TCP_Ports.txt
rm /tmp/UDP_Ports.txt

#############################
# unicornscan default range #
#############################
elif [ $PORTS = D ]; then

echo ""
echo "[*] Scanning Default TCP port range, be patient..."
unicornscan -mT -R2 -r $SPEED $TARGET &>/dev/null >> /tmp/TCP_Ports.txt &wait
echo "[>] TCP Ports:"
cat /tmp/TCP_Ports.txt

echo ""
echo "[*] Scanning Default UDP port range, be patient..."
unicornscan -mU -R2 -r $SPEED $TARGET &>/dev/null >> /tmp/UDP_Ports.txt &wait
echo "[>] UDP Ports:"
cat /tmp/UDP_Ports.txt

####################################
# Prepping output for amap && nmap #
####################################

########
# amap #
########

cat /tmp/TCP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' >> /tmp/amap_list.txt
cat /tmp/UDP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' >> /tmp/amap_list.txt

########
# nmap #
########

cat /tmp/TCP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' |sed 's/$/,/' |tr -d '\n' >> /tmp/nmap_list.txt
cat /tmp/UDP_Ports.txt |cut -d"[" -f2 |cut -d"]" -f1 |sed -e 's/^[ \t]*//' |sed 's/$/,/' |tr -d '\n' >> /tmp/nmap_list.txt

rm /tmp/TCP_Ports.txt
rm /tmp/UDP_Ports.txt

fi

###########################################
#  ~~~ Passing Ports to amap && nmap ~~~  #
###########################################

########
# nmap #
########

if [ $ENUM = N ]; then

echo ""
echo "[*] Passing Ports to Nmap..."
for DARK in $(cat /tmp/nmap_list.txt); do
nmap -sS -sV -p $DARK $TARGET >> nmap-output.txt; done
echo ""
echo "[>] Done!! Check out nmap-output.txt..."

########
# amap #
########

elif [ $ENUM = A ]; then

echo ""
echo "[*] Passing Ports to Amap..."
for SHARK in $(cat /tmp/amap_list.txt); do
amap -Adbqv -1 -b $TARGET $SHARK >> amap-output.txt; done
echo ""
echo "[>] Done!! Check out amap-output.txt..."

################
# amap && nmap #
################

elif [ $ENUM = B ]; then

echo ""
echo "[*] Passing Ports to Nmap & Amap..."
for DARK in $(cat /tmp/nmap_list.txt); do
nmap -sS -sV -p $DARK $TARGET >> nmap-output.txt; done
for SHARK in $(cat /tmp/amap_list.txt); do
amap -Adbqv -1 -b $TARGET $SHARK >> amap-output.txt; done
echo ""
echo "[>] Done!! Check out nmap-output.txt and amap-output.txt..."

fi

######################################
#  ~~~ Clean up temporary files ~~~  #
######################################

rm /tmp/amap_list.txt &>/dev/null
rm /tmp/nmap_list.txt &>/dev/null

##############################################
#  ~~~ Parsing Keywords in Searchsploit ~~~  #
##############################################

####################
# searchsploit = y #
####################

if [ $XPLOIT = Y ]; then

echo ""
echo "[*] Searching in searchsploit"
echo "[Take some time to go through the output files and group together"
echo " keywords seperated by comma's and all in lower-case see the"
echo " following example => freebsd local, sendmail 8.*]" 
echo ""
echo -n "[>] Input search-string: "
read -e SEARCH

echo ""
echo $SEARCH |tr ',' '\n' |sed -e 's/^[ \t]*//' >> /tmp/search.txt

while IFS= read -r line; do
/pentest/exploits/exploitdb/searchsploit $line
done < /tmp/search.txt

rm /tmp/search.txt

echo ""
echo "[>] Done!!"

####################
# searchsploit = n #
####################

elif [ $XPLOIT = N ]; then

echo ""
echo "[>] Done!! No searchsploit parsing to do..."

fi

exit