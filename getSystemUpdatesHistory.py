#!/usr/bin/python
#
# Author: philipp.schuler@holidaycheck.com
#
# Lists all packages installed on a given node after a datetime: -t DD.MM.YYYY_HH:MM:SS
# or after X hours before now: -d HOURS
# If no datetime is given, packages installed in past 24h are listed.

import xmlrpclib
import urllib2
import json
import sys, getopt
from datetime import datetime, timedelta

SATELLITE_URL = 'https://spacewalk.example.com'
SATELLITE_LOGIN = 'admin'
SATELLITE_PASSWORD = 'foobar'

date = datetime.today() - timedelta(hours=24)

def printUsage():
  print 'Usage: getSystemUpdatesHistory.py -h HOSTNAME [-t DD.MM.YYYY_HH:MM:SS | -d HOURS]'

try:
  opts, args = getopt.getopt(sys.argv[1:],"h:d:t:",["host=","delta=","timestamp="])
  if len(opts) == 0:
    printUsage()
    sys.exit(2)
except getopt.GetoptError:
  printUsage()
  sys.exit(2)

for opt, arg in opts:
  if opt in ('-h','--host'):
    host = arg
  elif opt in ('-t','--timestamp'):
    date = arg
    date = datetime.strptime(date,"%d.%m.%Y_%H:%M:%S")
  elif opt in ('-d','--delta'):
    date -= timedelta(hours=int(arg))
  else:
    printUsage()
    sys.exit(2)

client = xmlrpclib.Server(SATELLITE_URL+'/rpc/api', verbose=0)
key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)

# get system package history
system = client.system.search.hostname(key, host)
try:
  pkgs = client.system.listPackages(key, system[0]['id'])
except IndexError:
  print "No system found with this hostname"  
  sys.exit(2)

# filter packages by date and print result
for pkg in pkgs:
  installTime = datetime.strptime(pkg['installtime'].value,"%Y%m%dT%H:%M:%S")
  if installTime > date:
    pkgName = '%s-%s-%s' %(pkg['name'], pkg['version'], pkg['release'])
    if pkg['epoch'] != ' ' and pkg['epoch'] != '':
      pkgName += ':%s' % pkg['epoch']
    print installTime.strftime("%d.%m.%Y_%H:%M:%S") + '\t' + pkgName

client.auth.logout(key)