#!/usr/bin/env python
# encoding: iso8859-1
"""
main.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "2.0 Beta"

import sys
import os
from subprocess import call
import subprocess
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


# Verifies if the user that is executing LDLogger has administrator
# privileges. To do so, it's verified if the user has write
# permission on C:\Windows\system. If the user does not have permission,
# the program will call the method executeLDLoggerAsAdministrator().
def userHasAdministratorPrivileges():
  if not os.access("C:\Windows\system", os.W_OK):
    print " "
    print "O programa está sendo executado sem privilégios de administrador."
    print "Executando o LDLogger com privilégios de administrador."
    print " "
    executeLDLoggerAsAdministrator()
    #exit(1)

# Execute LDLogger
#
def executeLDLoggerAsAdministrator():
    #retcode = call(['runas', '/user:urias', 'python main.py'])
    #print "retcode", retcode
  if 0 != call(['runas', '/user:administrador', 'python main.py']):
    print >>sys.stderr, "Falha ao tentar executar o programa com o usuário adminstrador."
    exit(1)
  #  stderr=subprocess.STDOUT
   # print stderr
  
def main(argv):
  
  userHasAdministratorPrivileges()

  lists = instantiateLists()
  # it's just a test
  logger = ldlogger.LDLogger(VERSION)
  logger.executeLDLogger(lists)
  
  commandHandler.execute("start notepad LDLogger.txt")
  
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
