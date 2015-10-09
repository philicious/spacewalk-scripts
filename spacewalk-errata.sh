#!/bin/bash

# Processes Ubuntu Errata and imports them to Spacewalk

#make sure we have english locale
export LC_TIME="en_US.utf8"
# Obtains the current date and year.
DATE=`date +"%Y-%B"`
# Fetches the errata data from ubuntu.com.
rm -rf /opt/spacewalk-errata/errata/$DATE.txt
rm -rf /opt/spacewalk-errata/errata/ubuntu-errata.xml
curl https://lists.ubuntu.com/archives/ubuntu-security-announce/$DATE.txt.gz > /opt/spacewalk-errata/errata/$DATE.txt.gz
gunzip -f /opt/spacewalk-errata/errata/$DATE.txt.gz
# Processes and imports the errata.
cd /opt/spacewalk-errata/ && \
/opt/spacewalk-errata/parseUbuntu.py errata/$DATE.txt
/opt/spacewalk-errata/errata-import.py 2>&1 | tee -a /var/log/ubuntu-errata.log