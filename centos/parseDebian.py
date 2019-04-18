#!/usr/bin/python
#
# Author: robert.paschedag@netlution.de
#
# This script is adopted from the very good parseUbuntu.py of
# Philipp Schuler (philipp.schuler@holidaycheck.com)
#
# Changelog:
#
# 2016-05-10    Initial version
# 2018-03-12    Only parse new patches

import re
import urllib2
import os
import errno
import traceback
import sys
import xml.etree.cElementTree as XML


class MessageAnnounce:

    def __init__(self,
                 errata_type=None,
                 errata_name=None,
                 errata_id=None,
                 errata_release=None,
                 errata_year=None,
                 errata_severity=None,
                 errata_synopsis=None,
                 errata_date=None,
                 errata_from=None,
                 errata_desc=None,
                 errata_reboot='',
                 errata_dist=None,
                 msg_subject=None,
                 references=''):

        self.packages = {}
        self.cves = list()

        self.errataType = 'Security Advisory'
        self.errataName = errata_name
        self.errataID = errata_id
        self.errataRelease = errata_release
        self.errataYear = errata_year
        self.errataSynopsis = errata_synopsis
        self.errataDate = errata_date
        self.errataFrom = errata_from
        self.errataDesc = errata_desc
        self.errataReboot = errata_reboot
        self.errataDist = errata_dist
        self.messageSubject = msg_subject
        self.errataReferences = references

    def getAdvisoryName(self):
        advisory_name = "DSA-%s-%s" % (self.errataID, self.errataRelease)
        return advisory_name


class MessagePackageInfo:

    def __init__(self, pkg_release, pkg_file, pkg_version):
        self.release = pkg_release
        self.filename = pkg_file
        self.version = pkg_version


class MessageParser(object):
    # release should be the release of the channel we are working on
    #
    # global debian binary search url prefix
    SOURCE_URL = 'https://packages.debian.org/source'
    BIN_PACKAGELIST_REGEX = '^.*(?P<bin_packages><div.*following binary packages are built from this source.*?div>).*$'
    BIN_PACKAGE_REGEX = '<dt><a href.*?>(?P<package_name>.*?)</a></dt>'
    DIST = "distribution \((?P<dist>.*?)\)"
    VERSION = "version (?P<version>\S+?)(?=\.?( |$))"
    PKGINFO = "Package\s+:\s(?P<package_info>.*)"
    MAILING_LIST = "^Mailing list:"
    ERRATA_INFO = "_Subject_: \[SECURITY\] \[DSA (?P<errata_id>\d+)-(?P<errata_release>\d+)\] (?P<errata_name>\S+)( (?P<errata_other>.*))?$"
    DATE = "_Date_:\s+(?P<errata_date>.*?)(?=(\s\(.*\))?$)"
    FROM = "_From_:\s+(?P<errata_from>.*)$"
    CVE = "(?P<cve>CVE-\d{4}-\d{4})"
    EOH = '-----BEGIN PGP SIGNED MESSAGE-----'

    bin_packagelist_re = re.compile(BIN_PACKAGELIST_REGEX)
    bin_package_re = re.compile(BIN_PACKAGE_REGEX)
    pkginfo_re = re.compile(PKGINFO)
    mailing_list_re = re.compile(MAILING_LIST)
    erratum_info_re = re.compile(ERRATA_INFO)
    date_re = re.compile(DATE)
    from_re = re.compile(FROM)
    cve_re = re.compile(CVE)
    version_re = re.compile(VERSION)
    header_re = re.compile(r'^.*\s+:\s+.*$')
    eoh_re = re.compile(EOH)

    def _get_bin_packages(self, dist, sourcepackage):
        """
            Call url of source package
        """

        packages = []

        try:
            resp = urllib2.urlopen("%s/%s/%s" % (self.SOURCE_URL, dist, sourcepackage))
            url_data = re.sub("\n", "", resp.read())
            resp.close()
        except urllib2.HTTPError as e:
            print "Failed to fetch information for package '%s' in distribution '%s'" % (sourcepackage, dist)
            print e.reason
            return packages

        # search for package list match
        packages_match = self.bin_packagelist_re.search(url_data)

        if packages_match:
            packages = self.bin_package_re.findall(packages_match.group('bin_packages'))

        return packages

    # parse reboot
    def processMessageReboot(self, message_body):
        reboot = ''

        if message_body.find('to reboot') != -1:
            reboot = 'reboot_suggested'

        return reboot

    # parse the summary and details
    def processMessageSummary(self, message_body):
        summary = ''
        summary_found = False
        package_found = False
        header_found = False

        for line in message_body.split('\n'):
            # this parsing sucks...
            # sorry...Debian....but parsing Ubuntu security is easier ;-)
            # we start finding the package re, and continue
            # to ignore all following "header" lines. The first
            # non-header line marks our "summary"
            package_match = MessageParser.pkginfo_re.match(line)
            header_match = MessageParser.header_re.match(line)
            mailing_match = MessageParser.mailing_list_re.match(line)

            # set our flag if found...
            if header_match:
                header_found = True

            # set if not found
            if not header_match:
                header_found = False

            if package_match:
                package_found = True

            # end of summary ? Found line "Mailing list:"?
            if mailing_match:
                break

            # continue, until we find a Package line
            if not package_found:
                continue

            # continue, if we are still in header section
            if package_found and header_found:
                continue

            # because package_found stays True if found once, here, header_found
            # must be False, which indicates our summary beginning
            summary_found = True

            if summary_found:
                summary += line + '\n'

        if summary == '':
            summary = 'Parsing description failed'

        return summary

    def processMessageCVEs(self, message_body):
        cves = list()

        for line in message_body.split('\n'):
            cve_match = re.findall(MessageParser.CVE, line)
            if cve_match:
                cves.extend(cve_match)

        # generate list with unique cves
        cves = list(set(cves))
        return cves

    # parse the message summary for version strings and build "filenames"
    # incomplete filenames. REAL filenames have to be searched later.
    # "all-deb" packages also possible in amd64-deb channel!!!
    def processPackageList(self, err_name, message_body):
        current_release = None
        dist_packages = {}

        # for each "paragraph"
        for p in message_body.split('\n\n'):
            p = re.sub("\n", "", p)

            dists = re.findall(MessageParser.DIST, p)
            v_match = MessageParser.version_re.search(p)
            mailing_match = MessageParser.mailing_list_re.match(p)

            # if we ran over the packages, then stop
            if mailing_match:
                break

            if dists and v_match:
                for dist in dists:
                    # get all binary packages this "source" package creates
                    bin_packages = self._get_bin_packages(dist, err_name)
                    if not bin_packages:
                        continue
                    dist_packages[dist] = [pkg + '-' + v_match.group('version') for pkg in bin_packages]

        return dist_packages

    # Construct the basic details about the errata from the message subject
    def processMessageSubject(self, message_subject):
        subject_found = False

        parsed_msg = MessageAnnounce()

        for line in message_subject.split("\n"):
            erratum_info_match = MessageParser.erratum_info_re.search(line)
            eoh_match = MessageParser.eoh_re.search(line)
            date_match = MessageParser.date_re.search(line)
            from_match = MessageParser.from_re.search(line)

            if eoh_match:
                break

            if erratum_info_match:
                subject_found = True
                # in very few security announcements, the subject line is not consistent
                # and "errata_other" might not be found
                if erratum_info_match.group('errata_other') is None:
                    parsed_msg.messageSubject = parsed_msg.errataSynopsis = erratum_info_match.group('errata_name')
                else:
                    parsed_msg.messageSubject = parsed_msg.errataSynopsis = erratum_info_match.group('errata_name') + ' ' + erratum_info_match.group('errata_other')
                parsed_msg.errataName = erratum_info_match.group('errata_name')
                parsed_msg.errataID = erratum_info_match.group('errata_id')
                parsed_msg.errataRelease = erratum_info_match.group('errata_release')
                # parsed_msg.errataSynopsis = erratum_info_match.group('errata_name') + ' ' + erratum_info_match.group('errata_other')
                continue

            if date_match:
                parsed_msg.errataDate = date_match.group('errata_date')
                continue

            if from_match:
                parsed_msg.errataFrom = from_match.group('errata_from')
                continue

        if not subject_found:
            print "Message not parseable"
            return None

        return parsed_msg

    # Processes an individual mailing list message and returns a messageAnnounce object or none if parsing failed
    # Really bad parsing errors lead to an exception
    def processMessage(self, message_text):
        try:
            parsed_msg = self.processMessageSubject(message_text)

            if parsed_msg is None:
                return None

            parsed_msg.packages = self.processPackageList(parsed_msg.errataName, message_text)
            parsed_msg.errataDesc = self.processMessageSummary(message_text)
            parsed_msg.errataReboot = self.processMessageReboot(message_text)
            # parsed_msg.errataReferences = self.processMessageReferences(message_text)
            parsed_msg.cves = self.processMessageCVEs(message_text)

            return parsed_msg
        except Exception, e:
            print "Failed to process message. Reason:"
            print e
            traceback.print_exc(file=sys.stdout)

        return None

    # Performs parsing on the specified errata source. What this
    # actually means will vary between the different parsers
    # Will return list of MessageAnnounce objects, or throw an exception
    def parse(self):
        raise NotImplementedError("This method is implemented in subclasses, you should not call it from MessageParser")


class MessageFile(MessageParser):

    def __init__(self, input_file):
        self.inputFile = input_file

    def parse(self):
        inputData = open(self.inputFile).read()

        return self.processMessage(inputData)


def main():

    security_msg = "/tmp/debian_security/"
    errata_file = 'debian-errata.xml'
    parsed_dir = security_msg + 'parsed/'

    try:
        os.stat(parsed_dir)
    except OSError:
        os.mkdir(parsed_dir)

    # remove errata_file from previous run
    try:
        os.remove(security_msg + errata_file)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise

    try:
        files = filter(lambda f: re.match('^\d{4}-msg\d{5}\.html', f), os.listdir(security_msg))
        parsed_files = filter(lambda f: re.match('^\d{4}-msg\d{5}\.html', f), os.listdir(parsed_dir))

        files_to_parse = list(set(files) - set(parsed_files))
        announcements = list()

        if not files_to_parse:
            print "No security announcements to parse today. Bye."
            sys.exit(0)

        if len(files_to_parse) != len(files):
            print "Ignoring %d old security announcements already parsed." % (len(files) - len(files_to_parse))

        for idx, f in enumerate(files_to_parse, start=1):
            print "Processing patch %d/%d (file: %s)" % (idx, len(files_to_parse), f)
            message_parser = MessageFile(os.path.join(security_msg, f))
            errata = message_parser.parse()
            if errata:
                announcements.append(errata)
                # move the file to our parsed files dir
                os.rename(security_msg + f, parsed_dir + f)

        # if there are no advisories, just quit
        if not announcements:
            print "No security announcements available or parseable. Bye."
            sys.exit(0)

        # write the advisory XML
        opt = XML.Element('patches')
        for advisory in announcements:
            adv = XML.SubElement(opt, advisory.getAdvisoryName())
            adv.set('description', advisory.errataDesc.strip())
            adv.set('issue_date', advisory.errataDate)
            adv.set('errataFrom', advisory.errataFrom)
            # prepend advisory name to synopsis. This makes it easier to search for the errata in Spacewalk WebUI
            adv.set('synopsis', advisory.getAdvisoryName() + ' ' + advisory.errataSynopsis)
            adv.set('release', advisory.errataRelease)
            adv.set('product', 'Debian Linux')
            adv.set('topic', 'N/A')
            adv.set('solution', 'N/A')
            adv.set('notes', 'N/A')
            if advisory.errataReboot != "":
                adv.set('keywords', advisory.errataReboot)
            adv.set('type', advisory.errataType)
            # adv.set('references', advisory.errataReferences.strip())

            # for every distribution (jessie, stretch, ...)
            # add the packages
            for dist in advisory.packages:
                d = XML.SubElement(adv, 'dist')
                d.set('name', dist)
                for package in advisory.packages[dist]:
                    pkg = XML.SubElement(d, 'package')
                    pkg.text = package

            # add CVEs
            for cve in advisory.cves:
                c = XML.SubElement(adv, 'cve')
                c.text = cve

        xml = XML.ElementTree(opt)
        xml.write(security_msg + errata_file)

    except Exception, e:
        print "Failed to parse messages due to exception %s" % e
        traceback.print_exc(file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()
