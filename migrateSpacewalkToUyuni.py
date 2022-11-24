#!/usr/local/bin/python3

import sys
from xmlrpc import client
import getpass

# Variables
SPACEWALK_URL = "https://avst-prod10.dyn.adaptavist.com/rpc/api"
SPACEWALK_CENTOS7_BASE_CHANNEL="centos-7-64bit"
SPACEWALK_LOGIN =  input("Please enter spacewalk username: ")
SPACEWALK_PASSWORD = getpass.getpass("Please enter spacewalk password: ")
UYUNI_URL = "https://uyuni.adaptavist.cloud/rpc/api"
UYUNI_LOGIN = input("Please enter uyuni username: ")
UYUNI_PASSWORD = getpass.getpass("Please enter uyuni password: ")
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

# connect to uyuni and login
uyuni = client.ServerProxy(UYUNI_URL, verbose=0)
uyuni_key = uyuni.auth.login(UYUNI_LOGIN, UYUNI_PASSWORD)

# get the list of all systems subscribed to the base channel
systemList = spacewalk.channel.software.listSubscribedSystems(spacewalk_key, SPACEWALK_CENTOS7_BASE_CHANNEL)
systemList = [spacewalk.system.getName(spacewalk_key, 1000011139)]
for system in systemList:
   sysName = system.get("name")
   sysId = system.get("id")
   debug("Found system name: " + sysName)

   # right, lets now see if we can find the system in uyuni
   uyuniSystem = uyuni.system.searchByName(uyuni_key, "^" + sysName + "$")
   if uyuniSystem:
      channelsToAdd = []
      groupsToAdd = []
      # get a list of all the sub-channels the system is subscribed to in spacewalk
      channelList = spacewalk.system.listSubscribedChildChannels(spacewalk_key, sysId)
      for channel in channelList:
         channelName = channel.get("name")
         channelLabel = channel.get("label")
         debug("\tIt is subscribed to sub-channel: " + channelName)
         # make sure we can find the same channel in Uyuni
         try:
            uyuniChannel = uyuni.channel.software.getDetails(uyuni_key,channelLabel)
         except:
            uyuniChannel = None

         if not uyuniChannel:
            error ("Unable to find channel " + channelName + " in Uyuni, will not be able to subscribe system " + sysName + "to it, PLEASE MANUALLY FIX")
         else:
            info("Will Attempt to subcribe system " + sysName + " to channel " + channelLabel + " in uyuni")
            channelsToAdd.append(channelLabel)

      groupList = spacewalk.system.listGroups(spacewalk_key, sysId)
      for group in groupList:
         groupName = group.get("system_group_name")
         groupId = group.get("id")
         # hack to work around the fact the "Adaptavist MS" group in Spacewalk has an extra space but not in Uyuni!!
         if groupName == "Adaptavist  MS":
            groupName = "Adaptavist MS"
         if group.get("subscribed") == 1:
            debug("\tIt is a member of group: " + groupName)
            # make sure the group exists in uyuni
            try:
               uyuniGroup = uyuni.systemgroup.getDetails(uyuni_key, groupName)
            except:
               uyuniGroup = None

            if not uyuniGroup:
               error ("Unable to find group " + groupName + " in Uyuni, will not be able to subscribe system " + sysName + "to it, PLEASE MANUALLY FIX")
            else:
               # subscribe to the group
               info("Will Attempt to add system " + sysName + " to group " + groupName + " in uyuni")
               try:
                  uyuni.system.setGroupMembership(uyuni_key, uyuniSystem[0].get("id"),uyuniGroup.get("id"),True)
               except:
                  error("Unable to add system " + sysName + " to group " + groupName + ", PLEASE MANUALLY FIX")
               

      # subscribe to all the sub-channels
      try:
         uyuni.system.setChildChannels(uyuni_key, uyuniSystem[0].get("id"), channelsToAdd)
      except:
         error("Unable to add system " + sysName + " to one or more below channels, PLEASE MANUALLY FIX")
         for badChannel in channelsToAdd:
            error("\t * " + badChannel)

   else:
      error("Unable to find matching system, " + sysName + ", in Uyuini" )
   

# logout
spacewalk.auth.logout(spacewalk_key)
uyuni.auth.logout(uyuni_key)