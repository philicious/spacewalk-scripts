#!/bin/env python
#
# This script is adopted from errata-import.py from
# Pedro Andujar || twitter: pandujar || email: @segfault.es || @digitalsec.net
#
# Robert Paschedag <robert.paschedag@netlution.de>
#
# Changelog:
# 2016-08-08 - Print start of script with debug_level
# 2016-08-01 - Changed logging
# 2016-07-27 - Don't publish errata into excludedChannels
# 2016-05-24 - Initial working version

from __future__ import print_function

import sys
import xmlrpclib
import os
import errno
from datetime import datetime
import xml.etree.cElementTree as xml
from optparse import OptionParser

debug_level = 0

parser = OptionParser()
parser.add_option("-d", "--debug", action="store", dest="debug_level", type="int", help="set debug level")

(option, args) = parser.parse_args()

if option.debug_level is not None and option.debug_level > 0:
    debug_level = option.debug_level

# Config Settings#
filename = '/tmp/debian_security/debian-errata.xml'
excludedChannels = ['wheezy_main',
                    'jessie_main',
                    'stretch_main_main']
includedChannels = ['jessie_security_main',
                    'jessie_security_contrib',
                    'jessie_security_non-free',
                    'stretch_security_main',
                    'stretch_security_contrib',
                    'stretch_security_non-free']
# Config Settings#

url = 'http://localhost/rpc/api'
login = ''
passwd = ''
key = ''
client = ''
erratum = ''
issue_date = ''
erratainfo = {}
keywords = []
packages = {}
bug = []
publish = True
attempts = 0


# xmlrpc connect to server and retrieve key
def connect(url, login, passwd):
    try:
        global client, key
        client = xmlrpclib.Server(url, verbose=0)
        key = client.auth.login(login, passwd)
        log(1, "[+] Connected to %s" % url)
    except Exception, e:
        log(1, "[-] Error connecting to %s: %s" % (url, e))
        sys.exit(1)


def logout(key):
    client.auth.logout(key)
    log(1, "[-] Clossing Session on %s" % url)


def log(level, s, f=sys.stdout):
    """
    Write s to file f if l is smaller or equal to current debug level
    Print _always_ if f == sys.stderr
    """
    if level <= debug_level or f == sys.stderr:
        print(s, file=f)


def createPackageList(client, key):
    try:
        log(1, "[+] Creating inventory from Server:")
        if not includedChannels:
            log(1, "[+] Retrieving the list of available channels")
            tmpchannels = client.channel.listSoftwareChannels(key)
            for label in tmpchannels:
                if label.get('label') in excludedChannels:
                    log(1, "[-] Excluding channel: %s" % label.get('label'))
                else:
                    log(1, "[+] Including channel: %s" % label.get('label'))
                    includedChannels.append(label.get('label'))
        else:
            log(1, "[+] Including channel(s): %s" % includedChannels)

        for label in includedChannels:
            log(1, "[+] Retrieving Package List from Channel: %s" % label)
            tmppackages = client.channel.software.listAllPackages(key, label)
            for package in tmppackages:
                # this will not work 100% because some packages are named like
                # '...all-deb.deb', so for all architectures! We need to find the
                # real name

                # sep = '-'
                # packinfo = package["name"], package["version"], package["release"]
                # fullpack = sep.join(packinfo) + '.amd64-deb.deb'
                try:
                    packinfo = client.packages.getDetails(key, package['id'])
                    if not packinfo:
                        log(10, "[-] Error retrieving package details for package id %d" % package['id'], sys.stderr)
                        continue
                except:
                    log(10, "[-] Error retrieving package details for package id %d" % package['id'], sys.stderr)
                    continue

                # this generates a hash of "package" objects (which contains "filename", etc.)
                if not package['id'] in packages:
                    packages[package['id']] = packinfo
    except Exception, e:
        log(10, "[-] Error creating PackageList: %s" % e, sys.stderr)


def getPackagesAndChannels(filenames, packages, dist):
    """Given a list of incomplete package filenames, searches
       within 'packages' for a matching package object
       It also verifies, that all packages
       have been found within the same channel. Erratas with
       packages divided into different channels might not
       be deployable because a client might not subscribe
       to all needed channels"""

    packages_found = []
    c = set()

    p1 = []
    # for every filename
    for filename in filenames:
        # first....find packages with "matching" filenames
        for pkg in filter(lambda x: packages[x]['file'].startswith(filename), packages.keys()):
            p1.append(packages[pkg])

    # only include packages that have been found in channels where the label "starts" with
    # the distribuion name (dist == "jessie" gets packages from "jessie_security_main",
    # "jessie_security_contrib" but not "wheezy_security_main")
    for p in p1:
        for chan in p['providing_channels']:
            if chan.startswith(dist):
                packages_found.append(p)

    # each package within a "patch" must be within the same channels as the others
    for idx, package in enumerate(packages_found):
        if idx == 0:
            # set has to be "initialized" in "first" run
            # otherwise there would never be a positive
            # intersection
            c = set(package['providing_channels'])
        else:
            # build intersection. c is empty, if no channel
            # is found in the other package and vice versa
            c &= set(package['providing_channels'])

        # because there is still bug https://bugzilla.redhat.com/show_bug.cgi?id=1243387 present
        # do NOT touch "main" channels (given in excludedChannels). If a "package" is also provided
        # by one of these "main" channels, remove that channel! Otherwise, that "main" channel would
        # get updates (by taskomatic) and the "Packages" file would get regenerated (in wrong way :-( )

        # just test if a "main" channels would get updated and report that...
        if excludedChannels and c & set(excludedChannels):
            log(2, "Package '%s' is also provided by at least one excluded channel: (%s). This will be ignored here. Please check." % (
                package['file'],
                ', '.join(excludedChannels)
            ))

        # remove the possible "main" channels
        c -= set(excludedChannels)

        if not c:
            # once the set is empty, no need to continue
            break

    if not c:
        # return empty list of packages and empty list of channels
        # if all packages are not within the same channel
        return [], []

    # we only need the ids here
    return [p['id'] for p in packages_found], list(c)


# Check if the errata already exist or check if its applicable to any channel
def getDetailsErratum(client, key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels):
    try:
        eDetails = client.errata.getDetails(key, erratum)
        log(1, "[-] %s already exist: check if update needed..." % erratum)
        # generate sets of the packages currently included within this errata and
        # from this *new* packageids. Packageids NOT within existing erratum is calculated with
        #
        # missing_ids = list(set(new packageids) - set(list of current packages in errata))
        missing_ids = list(set(packageids) - set([x['id'] for x in client.errata.listPackages(key, erratum)]))
        if missing_ids:
            log(1, "[+] adding %d missing packages to erratum %s" % (len(missing_ids), erratum))
            try:
                ret = client.errata.addPackages(key, erratum, missing_ids)
                if ret != len(missing_ids):
                    log(1, "[-] only %d of %d packages have been added to errata %s" % (ret, len(missing_ids), erratum))
            except:
                log(1, "[-] update of errata %s failed!" % erratum)
        else:
            log(1, "[+] %s is up-to-date" % erratum)
        return
    except xmlrpclib.Fault:
        log(0, "[+] %s doesn't exist: creating" % erratum)
        createErratum(client, key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels)


# Create and publish errata
def createErratum(client, key, erratum, issue_date, erratainfo, keywords, packageids, cves, publish, channels):
    try:
        log(1, "[+] Creating errata %s:" % erratum)
        log(2, client.errata.create(key, erratainfo, bug, keywords, packageids, publish, channels))
        # Include aditional info using setDetails method (not supported by create method)
        # http://www.spacewalkproject.org/documentation/api/2.3/handlers/ErrataHandler.html#setDetails
        client.errata.setDetails(key, erratum, {'update_date': issue_date})
        client.errata.setDetails(key, erratum, {'issue_date': issue_date})
        if publish:
            client.errata.setDetails(key, erratum, {'cves': cves})
    except Exception, e:
        log(10, "[-] Error creating errata: %s" % e, sys.stderr)


def parseXML(client, key, filename):
    try:
        log(1, "[+] Retrieving data from %s" % filename)
        global erratum, erratainfo, newpackages, cves, issue_date, packageids, channels
        adv = xml.parse(filename).getroot()
        for element in adv:
            # Resetting values
            newpackages = []
            cves = []
            packageids = []
            channels = []
            keywords = []
            references = ''
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
            if element.get('keywords'):
                keywords = [element.get('keywords')]
            advisory_type = element.get('type')
            if element.get('references'):
                references = element.get('references')

            for cve in element.findall('cve'):
                cves.append(cve.text)
            # go through all "dists" and create an errata for every distribution
            # the name of the distribution will be prepended to build the advisory_name
            # (e.g. given "DSA-1234-1", will create "jessie-DSA-1234-1")
            for dist in element.findall('dist'):
                # change the erratum (advisory_name). Prepend dist
                distname = dist.get('name')
                dist_erratum = distname + '-' + erratum
                newpackages, channels = getPackagesAndChannels([p.text for p in dist.findall('package')], packages, distname)
                if not newpackages:
                    log(2, "[-] Error finding packages for advisory %s for distribution %s." % (erratum, distname))
                    # continue with next distribution
                    continue

                # Prepare struct for method
                # create:http://www.spacewalkproject.org/documentation/api/2.3/handlers/ErrataHandler.html#create
                erratainfo = {'synopsis': synopsis, 'advisory_name': dist_erratum, 'advisory_release': release,
                              'advisory_type': advisory_type, 'product': product, 'errataFrom': errataFrom,
                              'topic': topic, 'description': description, 'references': references, 'notes': notes,
                              'solution': solution}
                getDetailsErratum(client, key, dist_erratum, issue_date, erratainfo, keywords, newpackages, cves,
                                  publish, channels)
    except Exception, e:
        log(10, "[-] Error parsing %s: %s" % (filename, e), sys.stderr)


def main():
    print("Started errata import..... Debug level: %d" % debug_level)
    try:
        os.stat(filename)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise

    connect(url, login, passwd)
    createPackageList(client, key)
    parseXML(client, key, filename)
    logout(key)
    print("Finished errata import")


if __name__ == "__main__":
    main()
