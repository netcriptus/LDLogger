#!/usr/bin/env python
# encoding: iso8859-1
"""
main.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "2.0 Beta"

import sys
from lists import *
from ctypes import *
from utils import ldlogger, errorHandler, commandHandler

def instantiateLists():
  lists = {}
  
  try:
    lists["REG_KEYS"] = REG_KEYS_LIST.REG_KEYS
    lists["BROWSERS"] = BROWSERS_LIST.BROWSERS
    lists["svchost_whitelist"] = svchostWhitelist.svchost_whitelist
    lists["winlogon_whitelist"] = winlogon_whitelist.winlogon_whitelist
    lists["associations"] = associations.associations
    lists["services_whitelist"] = srv_and_drvs_whitelist.services_whitelist
    lists["drivers_whitelist"] = srv_and_drvs_whitelist.drivers_whitelist
  except Exception as err:
    errorHandler.logError("List instantiation", err)
  return lists


def userIsAdmin():
  """Verify if the program is running with administrator privileges"""
  return windll.shell32.IsUserAnAdmin()


def main(argv):  
  
  if not userIsAdmin():
    # place a visual error message here
    return 1
  lists = instantiateLists()
  # it's just a test
  logger = ldlogger.LDLogger(VERSION)
  logger.executeLDLogger(lists)
  
  commandHandler.execute("start notepad LDLogger.txt")
  
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
