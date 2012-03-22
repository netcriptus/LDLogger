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
  try:
    subprocess.call(command, shell=True)
  except Exception as err:
    errorHandler.errorLog("executing " % command, err)


def getOutput(command):
  try:
    return subprocess.check_output(command, shell=True)
  except Exception as err:
    errorHandler.logError("getOutput of " % command, err)
    return None
