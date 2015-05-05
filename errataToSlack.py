#!/usr/bin/python
#
# Author: philipp.schuler@holidaycheck.com
#

import xmlrpclib
import urllib2
import json

SATELLITE_URL = 'https://spacewalk.example.com'
SATELLITE_LOGIN = 'admin'
SATELLITE_PASSWORD = 'foobar'
SLACK_HOOK_URL = 'https://hooks.slack.com/services/winner_winner_chicken_diner'

collectedErrata = {}

client = xmlrpclib.Server(SATELLITE_URL+'/rpc/api', verbose=0)
key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)

# collect errata
systems = client.system.listSystems(key)
for system in systems:
  relevantErratas = client.system.getRelevantErrataByType(key, system['id'], 'Security Advisory')
  for relevantErrata in relevantErratas:
    try:
      errata = collectedErrata[relevantErrata['id']]
      errata['systemCount'] += 1
      collectedErrata[relevantErrata['id']] = errata
    except KeyError:
      thisErrata = {'id': relevantErrata['id'], 'systemCount': 1, 'name': relevantErrata['advisory_name'], 'synopsis': relevantErrata['advisory_synopsis'], 'date': relevantErrata['date']}
      collectedErrata[relevantErrata['id']] = thisErrata

# post errata to Slack
headers = {'content-type': 'application/json'}

for errata in collectedErrata.itervalues(): 
  text = "Spacewalk Errata Alert: <%s/rhn/errata/details/Details.do?eid=%d|%s %s>" % (SATELLITE_URL, errata['id'], errata['name'], errata['synopsis'])
  text += "\n<%s/rhn/errata/details/SystemsAffected.do?eid=%d|Affecting %d systems> since %s" % (SATELLITE_URL, errata['id'], errata['systemCount'], errata['date'])
  payload = {'text': text}
  
  req = urllib2.Request(SLACK_HOOK_URL)
  req.add_header('Content-Type', 'application/json')
  response = urllib2.urlopen(req, json.dumps(payload))

client.auth.logout(key)