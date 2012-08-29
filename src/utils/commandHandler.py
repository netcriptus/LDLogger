#!/usr/bin/env python
# encoding: utf-8
"""
commandHandler.py

Created by Fernando Cezar on 2012-03-21.
Copyright (c) 2012 __MyCompanyName__. All rights reserved.
"""

import subprocess
import errorHandler

def execute(command):
  """Given a command, it should be executed and show no return. If an error is
  generated, it should be logged"""
  try:
    subprocess.call(command, shell=True)
  except Exception as err:
    errorHandler.errorLog("executing %s " % str(command), err)


def getOutput(command):
  """Executes a command in the prompt and returns its result. In case of an
  error it returns am empty string"""
  try:
    return subprocess.check_output(command, shell=True)
  except Exception as err:
    errorHandler.logError("getOutput of %s " % str(command), err)
    return ""

def executeAsUser(command, user):
  """Given a command and an user, it should be executed and show no return.
  If an error is generated, it should be logged"""
  try:
    subprocess.call(['runas', 'user:'+user, command], shell=True)
  except Exception as err:
    errorHandler.errorLog("executing %s " % str(command), err)