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
import locale


# Instantiates lists and return a dict of lists.
#
# return lists
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
# permission on C:\Windows\system. It returns True if user has
# administrator privileges and False otherwise.
#
# return has_administrator_privileges
def userHasAdministratorPrivileges():
  try:
  # only windows users with admin privileges can read the C:\windows\temp
    temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\windows'),'temp']))
  except:
    return (False)
  else:
    return (True)


# Asks to user a login that has administrator privileges.
# To do so, the user types a login to LDLogger.
#
# return user
def asksAdministratorLoginToUser():
  print 'Digite o nome do usuário com privilégios de administrador: '
  user = sys.stdin.readline().strip()
  print 'user: ', user

  return user


def changeSpacesForSlashes(string):

  new_string = []

  for char in string:
    if ' ' == char:
      new_string.append('_')
    else:
      new_string.append(char)

  return ''.join(new_string)


def changeSlashesForSpaces(string):

  new_string = []

  for char in string:
    if '_' == char:
      new_string.append(' ')
    else:
      new_string.append(char)

  return ''.join(new_string)

# Executes LDLogger with administrator
# privileges. If current user has not those
# privileges, the program asks a login that
# has administrator privileges.
#
# see userHasAdministratorPrivileges()
# see asksAdministratorLoginToUser()
# see call()
def executeLDLoggerAsAdministrator(argv, dir_to_save_log):

  while False == userHasAdministratorPrivileges():
    print "\nO programa "+argv[0]+" está sendo executado sem privilégios de administrador."
    print "Executando o LDLogger com privilégios de administrador.\n"
    user = asksAdministratorLoginToUser()

    ldlogger_new_call = []
    ldlogger_new_call.append(argv[0])
    ldlogger_new_call.append(' --dir=')
    ldlogger_new_call.append(changeSpacesForSlashes(dir_to_save_log))

    print 'ldlogger_new_call: ', "".join(ldlogger_new_call)


#    if 0 != call(['runas', '/user:'+user, 'python main.py']):
    if 0 != call(['runas', '/user:'+user, "".join(ldlogger_new_call)]):
      print >>sys.stderr, "Falha ao tentar executar o programa com o usuário ", user
    else:
      sys.exit(0)


def verifyDirectoryToSaveLog(argv):
  dir = os.getcwd()

  print 'len(argv): ', len(argv)
#  print 'argv: ', argv

  if 2 == len(argv):

    argument = str(argv[1])

    print 'argument: ', argument

    if '--dir=' in argument:
      dir = changeSlashesForSpaces(argument[6:len(argument)])

  print 'dir: ', dir

  return dir


# Main function that executes LDLogger.
def main(argv):

  dir_to_save_log = verifyDirectoryToSaveLog(argv)

  executeLDLoggerAsAdministrator(argv, dir_to_save_log)

  lists = instantiateLists()

  # it's just a test
  logger = ldlogger.LDLogger(VERSION)
  logger.executeLDLogger(lists, dir_to_save_log)
  
  commandHandler.execute("start notepad "+dir_to_save_log+"\\LDLogger.txt")
  
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
