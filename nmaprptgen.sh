#!/bin/bash
#
# Copyright 2016... nmap.sh authors
#
# nmap.sh is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nmap.sh is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with nmap.sh.  If not, see <http:#www.gnu.org/licenses/>.
#
# Description:
#
# This tool was meant to show the attack surface of any given system/application that is possibly susceptible to any number of
# vulnerabilities.  
#
# Two directories are created - output and results - output will contain the raw data, and results will provide the report.
# smb-check-vulns.nse seems to be missing in th the lastest incarnation of nmap 7.0.1 so a copy (source: offensive-security) is made.
# Part of the checks is to take a snapshot of any websites running on the next work, so used an updated version of Trustwave's 
# http-screenshot.nse patched by afxdub
#
# The main tool is nmap, but additional logic will be incorporated as needed.  This script is based on thepcn3rd handy work, with
# a couple of changes.
#
# To use: See usage
#
# Defaults
output='/data/lab/results/exam/nmap'
results='/data/lab/results/exam/nmap/report'

function usage {
        echo "usage: $1"
        echo
        echo "      -h help:"
        echo
}

function updhtml {
lc=$1
sv=$2
for i in `ls $results/*.png | cut -d"/" -f5`;do
        hstat=""
        case `echo $i | sed 's/\.png//g' | cut -d"-" -f2` in
                443) hstat="https" ;;
                8443) hstat="https" ;;
                *) hstat="http" ;;
        esac
        b=${i/.png/ }
        b=${b/-/:}
        replace "Saved to $i" "<p><a href='$hstat://$b' target='_blank'>$hstat://$b</a></br><img src='$i'></p>" -- $results/$lc-$sv.html
done
}

while getopts "h" OPT; do
        case $OPT in
                h) usage $0; exit;;
                *) usage $0; exit;;
        esac
done


# For creating report from the XML results
if [ $(type xsltproc | wc -l) -lt 1 ]; then
        apt-get install xsltproc
fi

# Creates the output and the results directory if they need to be created
if [ ! -d $results ]; then
    mkdir $results
fi

cat << 'EOF' > $results/index.html
<!doctype html>
<html>
        <head>
                <title>Results Report</title>
        </head>
        <body>
EOF

for line in $(ls $output/*.xml | cut -d"/" -f7); do
    echo "Generate a report based on the Nmap results - $line"
    # Generate a report based on the results
    xsltproc $output/$line -o $results/$line.html  
    if [ -f $results/$line.html ]; then
    echo "<a href=\"" >> $results/index.html
    echo $results/$line.html
    echo $results/$line.html >> $results/index.html
    echo "\">" >> $results/index.html
    echo $line >> $results/index.html
    echo "</a></br>" >> $results/index.html
    fi
done

echo
echo "Updating the $location-nmap-HTTP-screenshot.html"
echo
#updhtml $location 'nmap-HTTP-screenshot'

cat << 'EOF3' >> $results/index.html
        </body>
</html>
EOF3
