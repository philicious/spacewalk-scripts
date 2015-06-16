#!/bin/env python
#
# Pedro Andujar || twitter: pandujar || email: @segfault.es || @digitalsec.net
# 
# Changelog:
# 2015-06-16 - Initial working version 

import xmlrpclib
from datetime import datetime
import xml.etree.cElementTree as xml

url = "http://localhost/rpc/api"
login = "login"
passwd = "password"
filename = 'ubuntu-errata.xml'
key = ''
erratum = ''
issue_date = ''
erratainfo = { }
keywords = [ ]
packages = [ ]
packageids = [ ]
newpackages = [ ]
cves = [ ]
bug = [ ]
client = ''
publish = True
channels = [ ]
excludedChannels = ['precise', 'trusty']
includedChannels = [ ]

#xmlrpc connect to server and retrieve key
def connect(url, login, passwd):
	global client
	global key
	client = xmlrpclib.Server(url, verbose=0)
	key = client.auth.login(login, passwd)
	print "[+] Connected to %s" % url
	
def logout(key):
	client.auth.logout(key)
	print "[-] Clossing Session on %s" % url

def CreatePackageList(key):
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
			print "[-] %s No related packages found: skipping" % erratum
		else:
			print "[+] Found %s packages related to %s: Publishing" % (len(packageids), erratum)
			createErratum(key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels)	

#Create and publish errata	
def createErratum(key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels):
	try:
		print "[+] Created errata %s:" % erratum
		print client.errata.create(key, erratainfo, bug, keywords, packageids, publish, channels)
#Include aditional info using setDetails method (not supported by create method)
#http://www.spacewalkproject.org/documentation/api/2.3/handlers/ErrataHandler.html#setDetails
		client.errata.setDetails(key, erratum, {'update_date': issue_date})
		client.errata.setDetails(key, erratum, {'issue_date': issue_date})
		client.errata.setDetails(key, erratum, {'keywords': keywords})
		client.errata.setDetails(key, erratum, {'cves': cves})
# Clearing arrays
		del newpackages[:]
		del packageids[:]
		del cves[:]
	except Exception, e:
		print "[-] Error creating errata: %s" % e

def parseXML(filename):
	print "[+] Retrieving data from %s" % filename
	global erratum, erratainfo, newpackages, cves, issue_date
	adv = xml.parse(filename).getroot()
	for element in adv:
		erratum = element.tag
   		description = element.get('description')
   		issue_date = datetime.strptime(element.get('issue_date')[:-6], '%a, %d %b %Y %H:%M:%S')
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
		erratainfo = {'synopsis': synopsis, 'advisory_name': erratum, 'advisory_release': release, 'advisory_type': advisory_type, 'product': product, 'topic': topic, 'description': description, 'references': references, 'notes': notes, 'solution': solution }
#Retrieve subelements (cves/packages) for setDetails
#[ p.text for p in adv.iter ('packages')]
		for package in element.iter('packages'):
			newpackages.append(package.text)
		for cve in element.iter('cves'):
			cves.append(cve.text)
		getDetailsErratum(key, erratum)
		
def main():
	connect(url, login, passwd)
	CreatePackageList(key)
	parseXML(filename)
	logout(key)

if __name__ == "__main__":
   	main()
