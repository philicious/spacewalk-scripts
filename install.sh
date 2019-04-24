#!/bin/bash
#
# About: Install Script of Spacewalk automatically
# Author: liberodark
# License: GNU GPLv3

#=================================================
# CHECK UPDATE
#=================================================

  update_source="https://raw.githubusercontent.com/liberodark/spacewalk-scripts/master/install.sh"
  version="0.0.4"

  echo "Welcome on Spacewalk Script Install $version"

  # make update if asked
  if [ "$1" = "noupdate" ]; then
    update_status="false"
  else
    update_status="true"
  fi ;

  # update updater
  if [ "$update_status" = "true" ]; then
    wget -O $0 $update_source
    $0 noupdate
    exit 0
fi ;

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

distribution=$(cat /etc/*release | head -n +1 | awk '{print $1}')

#==============================================
# SPACEWALK
#==============================================
echo "Install Script for Spacewalk"

# Check OS & spacewalk

  if [ $? != 1 ]; then

    if [[ "$distribution" =~ .CentOS || "$distribution" = CentOS ]]; then
      read -p "What is your user of spacewalk ?" user
      read -p "What is your password of spacewalk ?" password

      yum install -y html2text git
      mkdir -p /home/errata/spacewalk-scripts/
      git clone https://github.com/liberodark/spacewalk-scripts/
      mv spacewalk-scripts /home/errata/spacewalk-scripts
      cp -a spacewalk_sync_debian.cron /etc/cron.daily/spacewalk_sync_debian.cron
      sed -i "s@MYLOGIN@${user}@@g" /home/errata/spacewalk-scripts/errata-import-debian.py
      sed -i "s@MYPASSWORD@${password}@@g" /home/errata/spacewalk-scripts/errata-import-debian.py

    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian || "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      read -p "What is your ssh user of spacewalk ?" ssh_user
      read -p "What is your ssh password of spacewalk ?" ssh_password
      read -p "What is your ip of spacewalk ?" ssh_ip

      apt-get update
      apt-get install -y html2text git sshpass
      mkdir -p /home/errata/spacewalk-scripts/
      git clone https://github.com/liberodark/spacewalk-scripts/
      mv spacewalk-scripts /home/errata/spacewalk-scripts
      cp -a spacewalk_errata_debian.cron /etc/cron.daily/spacewalk_errata_debian.cron
      sed -i "s@ssh_user@${ssh_user}@@g" /etc/cron.daily/spacewalk_errata_debian.cron
      sed -i "s@ssh_password@${ssh_password}@@g" /etc/cron.daily/spacewalk_errata_debian.cron
      sed -i "s@ssh_ip@${ssh_ip}@@g" /etc/cron.daily/spacewalk_errata_debian.cron
      
    fi
fi
