#!/usr/bin/python
#
# Author: philipp.schuler@holidaycheck.com
#
# This script imports Debian/Ubuntu .deb packages to Spacewalk
# Its a drop-in replacement for https://github.com/stevemeier/spacewalk-debian-sync
# meaning the arguments are the same.
#
# If you dont run it on your Spacewalk server, you need to edit SPACEWALK_URL
#
# Changelog:
# 
# 2015-10-21 - Initial working version

import xmlrpclib
import re
import sys
import os
import getopt
import tempfile
import subprocess
from gzip import GzipFile
from StringIO import StringIO
from urllib import urlopen

SATELLITE_URL = 'https://localhost'

def printUsage():
  print 'Usage: debianSync.py --url=REPO_URL --channel=SATELLITE_CHANNEL --username=SATELLITEUSER --password=SATELLITE_PASS'
  print 'Usage: debianSync.py -r REPO_URL -c SATELLITE_CHANNEL -u SATELLITE_USER -p SATELLITE_PASS'

# read arguments
try:
  opts, args = getopt.getopt(sys.argv[1:],"r:c:u:p:",["url=","channel=","username=","password="])
  if len(opts) < 4:
    printUsage()
    sys.exit(2)
except getopt.GetoptError:
  printUsage()
  sys.exit(2)

for opt, arg in opts:
  if opt in ('-r','--url'):
    url = arg
  elif opt in ('-c','--channel'):
    channel = arg
  elif opt in ('-u','--username'):
    SATELLITE_LOGIN = arg
  elif opt in ('-p','--password'):
    SATELLITE_PASSWORD = arg
  else:
    printUsage()
    sys.exit(2)    

# sanitize repo URL
repoRoot = None
match = re.search(r'(.*ubuntu\/)', url) # Ubuntu repos store data under 'ubuntu/'
repoRoot = match.group(1) if match else repoRoot
match = re.search(r'(.*debian\/)', url) # Debian repos store data under 'debian/'
repoRoot = match.group(1) if match else repoRoot
match = re.search(r'(.*security\.debian\.org\/)', url) # security.debian repo stores data in /
repoRoot = match.group(1) if match else repoRoot

print "INFO: Repo URL:  %s" % url
print "INFO: Repo root: %s" % repoRoot

if not repoRoot:
  print 'ERROR: Could not determine repo root, please open a GitHub issue !'

# get package list for channel
client = xmlrpclib.Server(SATELLITE_URL+'/rpc/api', verbose=0)
key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)
pkgs = client.channel.software.list_all_packages(key, channel)
channelPkgs = {}

for pkg in pkgs:
  channelPkgs[pkg['checksum']] = 1
  
client.auth.logout(key)

# download package list from repo and parse it
url = urlopen(url+'Packages.gz')
gzipfile = GzipFile(fileobj=StringIO(url.read()))
pkgs = gzipfile.read()
syncPkgs = []
repoPkgCount = 0
syncedPkgCount = 0

for pkg in pkgs.split('\n\n'):
  repoPkgCount += 1
  for pkginfos in pkg.split('\n'):
    line = pkginfos.split(':')
    if line[0] == 'Filename': 
      filename = line[1].strip()
    elif line[0] == 'MD5sum':
      md5 = line[1].strip()
    elif line[0] == 'SHA1':
      sha1 = line[1].strip()
    elif line[0] == 'SHA256':
      sha256 = line[1].strip()

  if not md5 in channelPkgs and not sha1 in channelPkgs and not sha256 in channelPkgs:
    syncPkgs.append(filename)
  else:
    syncedPkgCount += 1

gzipfile.close()

print "INFO: Packages in repo: %d" % repoPkgCount
print "INFO: Packages synced: %d" % syncedPkgCount
print "INFO: Packages to sync: %d" % len(syncPkgs)

# download and push missing packages
synced = 0

for pkg in syncPkgs:
  synced += 1
  print "INFO: %d/%d: %s" % (synced, len(syncPkgs), os.path.basename(pkg))

  # download
  url = urlopen(repoRoot+pkg)
  pkgFile = open(tempfile.gettempdir()+'/'+os.path.basename(pkg),'wb')
  pkgFile.write(url.read())
  pkgFile.close()

  # push to spacewalk
  cmd = "rhnpush -c %s -u %s -p %s %s" % (channel, SATELLITE_LOGIN, SATELLITE_PASSWORD, pkgFile.name)
  rhnpush = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  ret = rhnpush.wait()
  os.remove(tempfile.gettempdir()+'/'+os.path.basename(pkg))
  if ret != 0:
    print "ERROR: rhnpush [ %s ] failed: %s" % (cmd, rhnpush.communicate())
    sys.exit(1)

print "INFO: Sync complete"