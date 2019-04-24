# Spacewalk Debian
Spacewalk Script Installer 

This script is for client / server installation.
- Centos = client and execute daily cron task for import errata and sync chanels.
- Debian = server and execute daily cron task for download errata and send on spacewalk.

## How to use :

Copy and Past in your terminal :

```bash
wget -Nnv https://raw.githubusercontent.com/liberodark/spacewalk-scripts/install.sh && chmod +x install.sh; ./install.sh
```

## How is work :

For Centos 7 is a client

Just install the script !

For Debian 9 is a server

Just install the script !
need to make a first ssh connexion on your spacewalk from this debian

## How is use manually :

### On Debian

- Install

```
apt install -y html2text git
```

- Download Scripts

```
git clone https://github.com/liberodark/spacewalk-scripts
```

- Need to edit spacewalk_errata_debian.cron with ip / user / password

```
nano spacewalk_errata_debian.cron
cp -a spacewalk_errata_debian.cron /etc/cron.daily/spacewalk_errata_debian.cron
```

- Install Files :

```
mkdir -p /home/errata/spacewalk-scripts/
mv spacewalk-scripts /home/errata/spacewalk-scripts
```

### On Centos


```
yum install -y git
```

- Download Scripts

```
git clone https://github.com/liberodark/spacewalk-scripts
```

- Need to install file 

```
nano spacewalk_sync_debian.cron
cp -a nano spacewalk_sync_debian.cron /etc/cron.daily/nano spacewalk_sync_debian.cron
```

- Edit errata-import-debian.py

```
nano errata-import-debian.py
login = 'MYLOGIN' # Line 46
password = 'MYPASSWORD' # Line 47
```

- Install Files :

```
mkdir -p /home/errata/spacewalk-scripts/
mv spacewalk-scripts /home/errata/spacewalk-scripts
```

## Debian 6.x / 7.x

Save your source list :

```cp -a /etc/apt/sources.list /etc/apt/sources.list.bak```

For Debian 6.x

```echo "deb http://archive.debian.org/debian/ squeeze main" > /etc/apt/sources.list```

For Debian 7.x

```echo "deb http://archive.debian.org/debian/ wheezy main" > /etc/apt/sources.list```

## Linux Compatibility :

- Debian 8.x / 9.x
- Centos 7.x


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
