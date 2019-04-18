#!/usr/bin/python -tt
#
# Author: robert.paschedag@netlution.de
#
# This script downloads the Debian security announcements
# and saves them to a temporary directory for later parsing
#
# Changelog:
#
# 2016-05-10 - Do not create subdirectories for the announcements
# 2016-05-02 - Initial working version

import re
import sys
import os
from datetime import date
import tempfile
import subprocess
from urllib import urlopen

# we download all security announcements from this year and the year before
years = [str(date.today().year - 1), str(date.today().year)]
base_url = 'https://lists.debian.org/debian-security-announce/'
tmp_dir = '/tmp/debian_security/'
msg_href_regex = re.compile('(?P<msg_ref>msg\d{5}\.html)')

# create temporary directory if not present
try:
    os.stat(tmp_dir)
except OSError:
    os.mkdir(tmp_dir)

for year in years:
    # show all announcements of the year
    year_url = urlopen(base_url + 'debian-security-announce-' + year + '/threads.html')
    for line in year_url:
        m = msg_href_regex.search(line)
        if m:
            # open msg....
            msg_url = urlopen(base_url + year + '/' + m.group('msg_ref'))
            # ... and write it to our temp directory
            with open(tmp_dir + year + '-' + m.group('msg_ref'), "w+") as tmp_msg:
                # tmp_msg.write(msg_url.read())
                # parse through html2text
                child = subprocess.Popen(['html2text', '-'], stdin=subprocess.PIPE, stdout=tmp_msg, stderr=None)
                ret = child.communicate(msg_url.read().replace('\r\n', '\n'))

sys.exit(0)
