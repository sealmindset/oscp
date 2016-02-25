#!/bin/bash

for url in $(zcat access_log.txt.gz | cut -d" " -f1 | uniq | sort -urn); do
        echo $url
done
