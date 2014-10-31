#!/bin/bash

# Processes Ubuntu Errata and imports them to Spacewalk

#make sure we have english locale
export LC_TIME="en_US.utf8"
# Obtains the current date and year.
DATE=`date +"%Y-%B"`
# Fetches the errata data from ubuntu.com.
rm -rf /opt/spacewalk-errata/errata/$DATE.txt
rm -rf /opt/spacewalk-errata/errata/ubuntu-errata.xml
wget -P  /opt/spacewalk-errata/errata https://lists.ubuntu.com/archives/ubuntu-security-announce/$DATE.txt.gz
gunzip -f /opt/spacewalk-errata/errata/$DATE.txt.gz
# Processes and imports the errata.
cd /opt/spacewalk-errata/ && \
/opt/spacewalk-errata/parseUbuntu.py errata/$DATE.txt && \
mv ubuntu-errata.xml errata/ubuntu-errata.xml
# exclude the main channel as updates are never pushed there
/opt/spacewalk-errata/errata-import.pl --server spacewalk.hc.lan --errata errata/ubuntu-errata.xml --user admin --pass XXX --publish --exclude-channels ubuntu12.04-main >> /var/log/ubuntu-errata.log
