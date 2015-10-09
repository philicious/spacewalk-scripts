#!/usr/bin/python
#
# Author: philipp.schuler@holidaycheck.com
# 
# Changelog:
# 
# 2015-06-17 - Include errataDate and errataFrom information (pandujar)
# 2015-02-19 - Apply Reboot Information (C.Stehle)
# 2015-02-10 - Fixed regression bug 
# 2015-02-06 - Fixed bug when "Summary" missing in USN breaking import
# 2015-01-28 - Fixed bug for USN with multiple sub-IDs breaking import 
# 2014-10-31 - Initial working version 

import email
import re
import traceback
import sys
import xml.etree.cElementTree as XML

class MessageAnnounce:

    def __init__(self,
                 errata_type=None,
                 errata_id=None,
                 errata_year=None,
                 errata_severity=None,
                 errata_synopsis=None,
                 errata_date=None,
                 errata_from=None,
                 errata_desc=None,
                 errata_reboot=None,
                 msg_subject=None,
                 references=None):
        
        self.packages = {}
        self.cves = list()

        self.errataType = 'Security Advisory' # Ubuntu USN only publishes Security Advisories
        self.errataID = errata_id
        self.errataYear = errata_year
        self.errataSynopsis = errata_synopsis
        self.errataDate = errata_date
        self.errataFrom = errata_from
        self.errataDesc = errata_desc        
        self.errataReboot = errata_reboot
        self.messageSubject = msg_subject
        self.errataReferences = references

    def getUSNUrl(self):
        usn_url = " http://www.ubuntu.com/usn/%s" % (self.errataID)
        return usn_url
        
    def getAdvisoryName(self):
        advisory_name="USN-%s" % (self.errataID) 
        return advisory_name        

class MessagePackageInfo:

    def __init__(self,pkg_release,pkg_file,pkg_version):
        self.release = pkg_release
        self.filename = pkg_file
        self.version = pkg_version

class MessageParser(object):
    RELEASE = "(?P<release>Ubuntu \d\d.\d\d LTS)"
    REFERENCES = "References:"
    SUMMARY = "Summary:"
    UPDATEINS = "Update instructions:"
    PKGINFO = "Package Information:"
    ERRATA_SUBJECT="\[USN-(?P<errata_id>\d+-\d+)\] (?P<other_info>.*)"
    ERRATA_PKGS = "\s\s(?P<pkg_filename>.*)\s(?P<pkg_version>.*)"
    CVE = "(?P<cve>CVE-\d{4}-\d{4})"

    erratum_subject_re = re.compile(ERRATA_SUBJECT)
    release_re = re.compile(RELEASE)
    packagelist_re = re.compile(ERRATA_PKGS)
    references_re = re.compile(REFERENCES)
    summary_re = re.compile(SUMMARY)
    update_re = re.compile(UPDATEINS)
    pkginfo_re = re.compile(PKGINFO)
 
    #parse reboot
    def processMessageReboot(self, message_body):
        reboot = ''

        if message_body.find('reboot your computer') != -1:
            reboot = 'reboot_suggested'

        return reboot

    #parse the summary and details
    def processMessageSummary(self, message_body):
        summary = ''
        summary_found = False

        for line in message_body.split('\n'):
            summary_match = MessageParser.summary_re.match(line)
            update_match = MessageParser.update_re.match(line)

            # end of summary ?
            if not update_match is None:
                break

            # start of summary ?
            if not summary_match is None:
                summary_found = True
                continue

            if summary_found:
                summary += line + '\r'    

        if summary == '': 
            summary = 'Parsing description failed'

        return summary

    #parse the references
    def processMessageReferences(self, message_body):
        references = ''
        references_found = False

        for line in message_body.split('\n'):
            references_match = MessageParser.references_re.match(line)
            pkginfo_match = MessageParser.pkginfo_re.match(line)

            #start of references?
            if not references_match is None:
                references_found = True
                continue

            #end of references?
            if not pkginfo_match is None:
                break

            if references_found:
                references += line.strip() + '\r'

        return references

    def processMessageCVEs(self, message_body):
        cves = list()
        references_found = False

        for line in message_body.split('\n'):
            references_match = MessageParser.references_re.match(line)
            cve_match = re.findall(MessageParser.CVE, line)
            pkginfo_match = MessageParser.pkginfo_re.match(line)

            #start of references?
            if not references_match is None:
                references_found = True
                continue

            #end of references?
            if not pkginfo_match is None:
                break

            if references_found and len(cve_match) > 0:
                cves += cve_match

        return cves        

    #Chop up message into lists of packages per Ubuntu release and return
    def processPackageList(self,message_body):
        current_release = None
        arch_packages={}

        for line in message_body.split('\n'):
            release_match = MessageParser.release_re.match(line)
            packagelist_match = MessageParser.packagelist_re.match(line)
            references_match = MessageParser.references_re.match(line)

            # if we ran over the packages, then stop
            if not references_match is None:
                break

            if not release_match is None:            
                current_release = release_match.group('release')
                arch_packages[current_release]=list()
            elif not (current_release is None or packagelist_match is None):
                arch_packages[current_release].append(MessagePackageInfo(current_release, packagelist_match.group('pkg_filename'), packagelist_match.group('pkg_version')))
                     
        return arch_packages

    #Construct the basic details about the errata from the message subject
    def processMessageSubject(self,message_subject):
        erratum_subject_match =  MessageParser.erratum_subject_re.match(message_subject)
    
        if erratum_subject_match is None:
            print "Message with subject '%s' doesnt appear to be an errata " % message_subject
            return None

        parsed_msg = MessageAnnounce()
        parsed_msg.messageSubject = re.sub("\s+"," ",message_subject)            
        parsed_msg.errataID = erratum_subject_match.group('errata_id')
        parsed_msg.errataSynopsis = erratum_subject_match.group('other_info')

        return parsed_msg
                
    #Processes an individual mailing list message and returns a messageAnnounce object or none if parsing failed
    #Really bad parsing errors lead to an exception
    def processMessage(self,message_text):        
        try:
            errataMsg = email.message_from_string(message_text)
            stripNewLine = re.compile('\n')

            erratum_subject = errataMsg.get("Subject")
            if erratum_subject is None:
                return None
            
            erratum_subject = stripNewLine.sub("",erratum_subject)            
            parsed_msg = self.processMessageSubject(erratum_subject)
            
            if parsed_msg is None:
                return None

            parsed_msg.packages = self.processPackageList(errataMsg.get_payload())
            parsed_msg.errataDesc = self.processMessageSummary(errataMsg.get_payload())
            parsed_msg.errataReboot = self.processMessageReboot(errataMsg.get_payload())
            parsed_msg.errataReferences = self.processMessageReferences(errataMsg.get_payload())
            parsed_msg.cves = self.processMessageCVEs(errataMsg.get_payload())
            parsed_msg.errataDate = errataMsg.get("Date")
            parsed_msg.errataFrom = errataMsg.get("From")
                    
            return parsed_msg
        except Exception, e:
            print "Failed to process message. Reason:"
            print e
            traceback.print_exc(file=sys.stdout)

        return None 
        
    
    #Performs parsing on the specified errata source. What this
    #actually means will vary between the different parsers
    #Will return list of MessageAnnounce objects, or throw an exception
    def parse(self):
        raise NotImplementedError("This method is implemented in subclasses, you should not call it from MessageParser")

class MessageArchiveFile(MessageParser):

    #Split on lines formatted thusly: From marc.deslauriers at canonical.com  Thu Oct  2 17:42:28 2014      
    ARCHIVE_SEPARATOR="From .*[A-Za-z]{3,3} [A-Za-z]{3,3} [ 0-9]{2,2} \d{2,2}:\d{2,2}:\d{2,2} \d{4,4}\n"
    splitter_re = re.compile(ARCHIVE_SEPARATOR)
    
    def __init__(self,input_file):
        self.inputFile = input_file

    def parse(self):
        inputData = open(self.inputFile).read()

        self.parsedMessages = list()
        
        for msg in MessageArchiveFile.splitter_re.split(inputData):
            processed = self.processMessage(msg)
            if processed is not None:
                self.parsedMessages.append(processed)
    
        return self.parsedMessages

def main():
    try:
        if len(sys.argv) < 2:
            print "Usage: parseUbuntu.py ubuntu-errata.txt"
            sys.exit()
            
        message_parser = MessageArchiveFile(sys.argv[1])
        parsed_messages = message_parser.parse()

        # write the advisory XML
        opt = XML.Element('opt')
        for advisory in parsed_messages:
            adv = XML.SubElement(opt, advisory.getAdvisoryName())
            adv.set('description', advisory.errataDesc.strip())
            adv.set('issue_date', advisory.errataDate)
            adv.set('errataFrom', advisory.errataFrom)
            adv.set('synopsis', advisory.errataSynopsis)
            adv.set('release', '1')
            adv.set('product', 'Ubuntu Linux')
            adv.set('topic', 'N/A')
            adv.set('solution', 'N/A')
            adv.set('notes', 'N/A')
            if advisory.errataReboot != "":
                adv.set('keywords', advisory.errataReboot)            
            adv.set('type', advisory.errataType)
            adv.set('references', advisory.errataReferences.strip())

            # add packages
            for release in advisory.packages:
                for package in advisory.packages[release]:
                    pkg = XML.SubElement(adv, 'packages')
                    #pkg.set('release', release)
                    pkg.text = package.filename.strip() + '-' + package.version.strip() + '.amd64-deb.deb'

            # add CVEs
            for cve in advisory.cves:
                cves = XML.SubElement(adv, 'cves') 
                cves.text = cve     

        xml = XML.ElementTree(opt)
        xml.write("ubuntu-errata.xml")

    except Exception,e:
        print "Failed to parse messages due to exception %s" % e
        traceback.print_exc(file=sys.stdout)
        sys.exit(2)        

if __name__ == "__main__":
    main()
