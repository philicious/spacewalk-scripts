#!/bin/env python
#
# Pedro Andujar || twitter: pandujar || email: @segfault.es || @digitalsec.net
# 
# Changelog:
# 2015-08-25 - Fix to support python2.6. Added reattempts
# 2015-06-19 - Limit description 4000 chars
# 2015-06-17 - Workarround for Spacewalk bug (adding packages after create)
# 2015-06-16 - Initial working version 

import sys
import xmlrpclib
from datetime import datetime
import xml.etree.cElementTree as xml

#Config Settings#
url = "http://localhost/rpc/api"
login = "login"
passwd = "password"
filename = 'ubuntu-errata.xml'
excludedChannels = ['precise', 'trusty'] # Scan all available channels except these ones
includedChannels = [ ] # Only scan channels on this list
#Config Settings#

key = ''
erratum = ''
issue_date = ''
erratainfo = { }
keywords = [ ]
packages = [ ]
bug = [ ]
client = ''
publish = True
attempts = 0

#xmlrpc connect to server and retrieve key
def connect(url, login, passwd):
  try:
    global client, key
    client = xmlrpclib.Server(url, verbose=0)
    key = client.auth.login(login, passwd)
    print "[+] Connected to %s" % url
  except Exception, e:
    print "[-] Error connecting to %s: %s" % (url, e)
    sys.exit(1)
  
def logout(key):
  client.auth.logout(key)
  print "[-] Clossing Session on %s" % url

def CreatePackageList(key):
  try:
    print "[+] Creating inventory from Server:"
    if not includedChannels:
      print "[+] Retrieving the list of available channels"
      tmpchannels =  client.channel.listSoftwareChannels(key)
      for label in tmpchannels:
        if label.get('label') in excludedChannels:
          print "[-] Excluding channel: %s" % label.get('label')
        else:
          print "[+] Including channel: %s" % label.get('label')
          includedChannels.append(label.get('label'))
    else:
      print "[+] Including channel(s): %s" % includedChannels
    
    for label in includedChannels:
      print "[+] Retrieving Package List from Channel: %s" % label
      tmppackages = client.channel.software.listAllPackages(key, label)
      for package in tmppackages:
        sep = '-'
        packinfo = package["name"], package["version"], package["release"]
        fullpack = sep.join(packinfo) + '.amd64-deb.deb'
        packages.append([fullpack, package['id'], label])
# packages.append([ '%s.amd64-deb.deb' % '-'.join(package["name"], package["version"], package["release"]), package['id'], label])
  except Exception, e:
    print "[-] Error creating PackageList: %s" % e
    
def getPackIds(key, packages):
  for line in packages:
    for p in newpackages:
      if p == line[0]:
        packageids.append(line[1])
        channels.append(line[2])

#Check if the errata already exist or check if its applicable to any channel
def getDetailsErratum(key, erratum):
  try:
    eDetails = client.errata.getDetails(key, erratum);
    print "[-] %s already exist: skipping" % erratum
    return
  except xmlrpclib.Fault:
    print "[+] %s doesn't exist: analyzing" % erratum
    getPackIds(key, packages)
    if not packageids:  
      print "[-] No related packages found: skipping"
    else:
      print "[+] Found %s packages related: Publishing" % len(packageids)
      createErratum(key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels)

#Create and publish errata  
def createErratum(key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels):
  try:
    print "[+] Creating errata %s:" % erratum
    print client.errata.create(key, erratainfo, bug, keywords, [], publish, list(set(channels)))
#Include aditional info using setDetails method (not supported by create method)
#http://www.spacewalkproject.org/documentation/api/2.3/handlers/ErrataHandler.html#setDetails
    client.errata.setDetails(key, erratum, {'update_date': issue_date})
    client.errata.setDetails(key, erratum, {'issue_date': issue_date})
    client.errata.setDetails(key, erratum, {'keywords': keywords})
    client.errata.setDetails(key, erratum, {'cves': cves})
    client.errata.addPackages(key, erratum, packageids)
  except Exception, e:
    print "[-] Error creating errata: %s" % e
    global attempts
    if attempts < 3:
      attempts += 1
      print "[x] Reattemp: %s" % attempts
      createErratum(key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels)
    else:
      attempts = 0

def parseXML(filename):
  try:
    print "[+] Retrieving data from %s" % filename
    global erratum, erratainfo, newpackages, cves, issue_date, packageids, channels
    adv = xml.parse(filename).getroot()
    for element in adv:
#Resetting values
      newpackages = [ ]
      cves = [ ]
      packageids = [ ]
      channels = [ ]
      erratum = element.tag
      description = element.get('description')[:4000]
      issue_date = datetime.strptime(element.get('issue_date')[:-6], '%a, %d %b %Y %H:%M:%S')
      errataFrom = element.get('errataFrom')
      synopsis = element.get('synopsis')
      release = int(element.get('release'))
      product = element.get('product')
      topic = element.get('topic')
      solution = element.get('solution')
      notes = element.get('notes')
      keywords = [ element.get('keywords') ]            
      advisory_type = element.get('type')
      references = element.get('references')
#erratainfo = element.attrib
#Prepare struct for method create:http://www.spacewalkproject.org/documentation/api/2.3/handlers/ErrataHandler.html#create
      erratainfo = {'synopsis': synopsis, 'advisory_name': erratum, 'advisory_release': release, 'advisory_type': advisory_type, 'product': product, 'errataFrom': errataFrom, 'topic': topic, 'description': description, 'references': references, 'notes': notes, 'solution': solution }
#Retrieve subelements (cves/packages) for setDetails
#[ p.text for p in adv.iter ('packages')]
      for package in element.findall('packages'):
        newpackages.append(package.text)
      for cve in element.findall('cves'):
        cves.append(cve.text)
      getDetailsErratum(key, erratum)
  except Exception, e:
    print "[-] Error parsing %s: %s" % (filename, e)
    
def main():
  connect(url, login, passwd)
  CreatePackageList(key)
  parseXML(filename)
  logout(key)

if __name__ == "__main__":
    main()
