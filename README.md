# Spacewalk Debian
Spacewalk Debian Installer

## How to use :

Copy and Past in your terminal :

```bash
wget -Nnv https://raw.githubusercontent.com/liberodark/nrpe-installer/install.sh && chmod +x install.sh; ./install.sh
```

## SELinux :


```bash
yum install -y policycoreutils-python
grep denied /var/log/audit/audit.log | audit2allow -M nrpe
semodule -i nrpe.pp
```

Or use nrpe from github :

```bash
wget -O nrpe.tar.gz https://github.com/liberodark/nrpe-installer/releases/download/1.0/nrpe.tar.gz
tar -xvf nrpe.tar.gz && sudo rm nrpe.tar.gz && semodule -i nrpe.pp
```

## Plugins Configuration :

```
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"
command[memory]=/usr/local/nagios/libexec/check_mem.sh -w 70% -c 90%
command[memory_min]=/usr/local/nagios/libexec/check_mem.sh -w 70% -c 90% # For minimal informations
command[cpu]=/usr/local/nagios/libexec/check_cpu_utilization.sh -w 70 -c 90
command[cpu_min]=/usr/local/nagios/libexec/check_cpu_utilization.sh -w 70 -c 90 # For minimal informations
command[users]=/usr/local/nagios/libexec/check_users -w 5 -c 10
command[load]=/usr/local/nagios/libexec/check_load -w 15,10,5 -c 30,25,20
command[check_load]=/usr/local/nagios/libexec/check_load -w 15,10,5 -c 30,25,20
command[swap]=/usr/local/nagios/libexec/check_swap -w 20% -c 10%
command[root_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p / -m
command[usr_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p /usr -m
command[var_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p /var -m
command[zombie_procs]=/usr/local/nagios/libexec/check_procs -w 5 -c 10 -s Z
command[total_procs]=/usr/local/nagios/libexec/check_procs -w 190 -c 200
command[proc_named]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C named
command[proc_crond]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:5 -C crond
command[proc_syslogd]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C syslog-ng
command[proc_rsyslogd]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C rsyslogd
```

## Debian 6.x / 7.x

Save your source list :

```cp -a /etc/apt/sources.list /etc/apt/sources.list.bak```

For Debian 6.x

```echo "deb http://archive.debian.org/debian/ squeeze main" > /etc/apt/sources.list```

For Debian 7.x

```echo "deb http://archive.debian.org/debian/ wheezy main" > /etc/apt/sources.list```

## Linux Compatibility :

- Debian 7.x / 8.x / 9.x
- Ubuntu 18.04


## Script informations :

- **getDebianAnnouncements.py** By https://github.com/rpasche This downloads all security announcements of debian from the current year and the year before and uses html2text to transform it to ascii text
- **parseUbuntu.py** parses https://lists.ubuntu.com/archives/ubuntu-security-announce/$DATE.txt.gz into an XML which can be read by errata-import.pl / errata-import.py
- **parseDebian.py** By https://github.com/rpasche the same as parseUbuntu.py, but parses all security announcements downloaded with getDebianAnnouncements.py and writes this to an XML file for later use with errata-import-debian.py
- **errata-import.pl** originally by Steve Meier http://cefs.steve-meier.de/ I just modified it slightly to work with Ubuntu USN.
- **errata-import.py** By https://github.com/pandujar Ported version of the previous one. Includes some enhancenments like date, author and better package processing. Its quite faster than the Perl version.
- **errata-import-debian.py** By https://github.com/rpasche This is the modified version of errata-import.py for Debian
- **errata.py** is the missing "action" for rhn_check so it can apply Errata. Copy it to /usr/share/rhn/actions 
Its just a copy of https://github.com/spacewalkproject/spacewalk/tree/master/client/rhel/yum-rhn-plugin/actions
- **spacewalk-errata.sh** is a Bash script which downloads the compressed security announces, calls parseUbuntu.py on them and finally calls errata-import.py to import the Errata. This script can be run as a Cronjob to automate things.
- **errataToSlack.py** reports all errata affecting at least one system to a Slack channel or group
- **getSystemUpdatesHistory.py** Lists all packages installed on a given node after a datetime or after X hours before now
If no datetime is given, packages installed in past 24h are listed.
- **import-old.sh** imports all errata from Jan 2012 to the month just before today when run; in effect provides constantly up-to-date ubuntu-errata.xml file
- **debianSync.py** Ported version of https://github.com/stevemeier/spacewalk-debian-sync . Its a drop-in replacement, meaning all arguments are the same
