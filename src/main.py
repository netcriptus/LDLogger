#!/usr/bin/env python
# encoding: iso8859-1
"""
main.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "1.5 Beta"

# TODO: I need to verify what libs are necessary inside main.py

import sys
from platform import win32_ver, architecture
from lists import *
from utils import ldlogger, regOps, processes, services, drivers, printer, commandHandler, errorHandler, smartStr

try:
  REG_KEYS = REG_KEYS_LIST.REG_KEYS
  BROWSERS = BROWSERS_LIST.BROWSERS
  svchost_whitelist = svchostWhitelist.svchost_whitelist
  winlogon_whitelist = winlogon_whitelist.winlogon_whitelist
  associations = associations.associations
  services_whitelist = srv_and_drvs_whitelist.services_whitelist
  drivers_whitelist = srv_and_drvs_whitelist.drivers_whitelist
except Exception as err:
  errorHandler.logError("List instantiation", err)

  
def main(argv):  

  # it's just a test
  ldlogger = ldlogger.LDLogger(VERSION)
  ldlogger.executeLDLogger()

  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
