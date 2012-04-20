#!/usr/bin/env python
# encoding: iso8859-1
"""
main.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "2.0 Beta"

# TODO: I need to verify what libs are necessary inside main.py

import sys
from platform import win32_ver, architecture
from lists import *
from utils import ldlogger, regOps, processes, services, drivers, printer, commandHandler, errorHandler, smartStr

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

  
def main(argv):  

  # it's just a test
  logger = ldlogger.LDLogger(VERSION)
  logger.executeLDLogger(lists)

  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
