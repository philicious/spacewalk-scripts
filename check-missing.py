#!/usr/local/bin/python3

import sys
from xmlrpc import client
import getpass

# Variables
SPACEWALK_URL = "https://avst-prod10.dyn.adaptavist.com/rpc/api"
SPACEWALK_LOGIN =  input("Please enter spacewalk username: ")
SPACEWALK_PASSWORD = getpass.getpass("Please enter spacewalk password: ")
DEBUG=False

# common functions
def debug(msg):
   if DEBUG == True:
      print("DEBUG: " + msg)

def info(msg):
   print("INFO: " + msg)

def error(msg):
   print("ERROR: " + msg)

## MAIN CODE STARTS HERE

# parse arguments (and yes this is poo but!!)
for arg in sys.argv:
   if arg == "-d" or arg == "--debug":
      DEBUG=True

# connect to Spacewalk and login
spacewalk = client.ServerProxy(SPACEWALK_URL, verbose=0)
spacewalk_key = spacewalk.auth.login(SPACEWALK_LOGIN, SPACEWALK_PASSWORD)

prod_systems=spacewalk.systemgroup.listSystems(spacewalk_key, "prod")
nonprod_systems=spacewalk.systemgroup.listSystems(spacewalk_key, "non-prod")
all_systems=spacewalk.system.listSystems(spacewalk_key)

for system in all_systems:
  found = False
  for prod in prod_systems:
     if system.get("name") == prod.get("profile_name"):
       found = True
  for stg in nonprod_systems:
     if system.get("name") == stg.get("profile_name"):
       found = True

  if found == False:
   info ("System " + system.get("name") + " is not in the prod OR non-prod groups")

# logout
spacewalk.auth.logout(spacewalk_key)

