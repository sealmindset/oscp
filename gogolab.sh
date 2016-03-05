#!/bin/sh

if [ $(ifconfig tap0 | wc -l) -lt 1 ]; then
cd /data/lab
./openlab
gnome-terminal -e "tcpdump -i tap0 not arp and not rarp"
gnome-terminal --working-directory=/data/lab/scripts/recon_scan 
else
echo "The Lab is already opened"
gnome-terminal -e "tcpdump -i tap0 not arp and not rarp"
gnome-terminal --working-directory=/data/lab/scripts/recon_scan 
fi
