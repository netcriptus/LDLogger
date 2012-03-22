#!/usr/bin/env python
# encoding: utf-8
"""
errorHandler.py

Created by Fernando Cezar on 2012-03-21.
Copyright (c) 2012 __MyCompanyName__. All rights reserved.
"""

def logError(local, error):
  status = open("error.txt", "a")
  status.write("There seems to be a problem on %s\n\n%s\n" % (local, str(type(error))))
  status.write("%s" % str(error.message))
  status.write("%s" % str(error.args))
  status.write("\n\n")
  status.close()