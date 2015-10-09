#!/bin/bash

# Imports old errata into spacewalk starting with Jan 2012 until the month before 
# today because that is the last full month of archives from USN

# Start import of Errata from Jan 2012
START_YEAR=12            #Change to last 2 digits of desired starting year

# Grab info about current month/year
CURR_YEAR=`date +"%y"`
CURR_MONTH=`date +"%B"`

# Helper funciton
function logger() {
  echo "INFO : $@"
}

# Fetch previous months errata
for y in $(eval echo "{${START_YEAR}..${CURR_YEAR}}"); do
  for m in January February March April May June July August September October November December; do
    if [ "$CURR_MONTH" = $m ] && [ "$CURR_YEAR" = $y ]; then
      logger "Current month and year reached, use 'spacewalk-errata.sh' to import this month's errata after current process finishes."
      break
    else
      # Download and extract archives from USN
      DATE="20${y}-${m}"
      logger "Downloading errata from $m 20$y..."
      curl --progress-bar https://lists.ubuntu.com/archives/ubuntu-security-announce/$DATE.txt.gz > /opt/spacewalk-errata/errata/$DATE.txt.gz
      gunzip -f /opt/spacewalk-errata/errata/$DATE.txt.gz
    fi
  done
done

# Combine logs into one file for import
cat /opt/spacewalk-errata/errata/*.txt > /opt/spacewalk-errata/errata/old.txt

# Processes and imports the errata
logger "Converting archives into XML for processing..."
cd /opt/spacewalk-errata/ && \
/opt/spacewalk-errata/parseUbuntu.py errata/old.txt
logger "Starting Errata importing..."
/opt/spacewalk-errata/errata-import.py 2>&1 | tee -a /var/log/ubuntu-errata.log
