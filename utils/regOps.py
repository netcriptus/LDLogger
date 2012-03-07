#!/usr/bin/env python
# encoding: iso8859-1
"""
regOps.py

Created by Fernando Cezar on 2011-12-02.
Copyright (c) 2011 __MyCompanyName__. All rights reserved.
"""
import _winreg
import types

def discoverValues(key, subkey):
  """
  Given a key and a subkey, what are the values under this address?
  It returns a list of values, or None, if the key and/or subkey are not valid
  """
  try:
    key = getattr(_winreg, key)
    handle = _winreg.OpenKey(key, subkey)
  except WindowsError:
    return None
  values = []
  i = 0
  while True:
    try:
      curr_value = _winreg.EnumValue(handle, i)[0]
    except WindowsError:
      break
    values.append(curr_value)
    i += 1
  return values or None


def discoverSubkeys(key, subkey):
  """
  Given a key and a subkey, what are the keys under this address?
  It returns a list of values, or None, if the key and/or subkey are not valid
  """
  try:
    key = getattr(_winreg, key)
    handle = _winreg.OpenKey(key, subkey)
  except WindowsError:
    return None
  keys = []
  i = 0
  try:
    while True:
      keys.append(_winreg.EnumKey(handle, i))
      i += 1
  except WindowsError:
    return keys


def getRegistryValue(key, subkey, value):
  """
  Returns the value of a registry, or None if the key, subkey or value are
  invalids
  """
  try:
    key = getattr(_winreg, key)
    handle = _winreg.OpenKey(key, subkey)
    (value, type) = _winreg.QueryValueEx(handle, value)
    return value
  except WindowsError:
    return None


def smart_str(s, encoding='utf-8', errors='ignore', from_encoding='iso8859-1'):
  if type(s) in (int, long, float, types.NoneType):
    return str(s)
  elif type(s) is str:
      return s.decode(from_encoding, errors).encode(encoding, errors)
  elif type(s) is unicode:
    return s.encode(encoding, errors)
  elif hasattr(s, '__str__'):
    return smart_str(str(s), encoding, errors, from_encoding)
  elif hasattr(s, '__unicode__'):
    return smart_str(unicode(s), encoding, errors, from_encoding)
  else:
    return smart_str(str(s), encoding, errors, from_encoding)


def getRegs(reg_list):
  """
  Given a list with keys, subkeys and values, it returns the content of those
  registers in a list. Any error on key, subkey or value will be ignored
  """
  regs = []
  for reg_key in reg_list:
    if reg_key["key"] == "Startups":
      regs.append("Startups")
      continue
    elif reg_key["key"] == "winlogon":
      regs.append("winlogon")
      continue
    
    values = reg_key["values"]
    if values == []:
      values = discoverValues(reg_key["key"], reg_key["subkey"])
      if not values:
        continue
      
    for value in values:
      try:
        content = getRegistryValue(reg_key["key"], reg_key["subkey"], value)
        if not content:
          continue
        try:
          value = smart_str(value)
        except Exception as err:
          log_error("smart_str value type: %s" % type(value), err)
        try:
          content = smart_str(content)
        except Exception as err:
          log_error("smart_str content type: %s" % type(content), err)
        regs.append("%s%s: %s" % (reg_key["tag"], value, content))
      except WindowsError:
        continue
  return regs
  
  
def log_error(local, err):
  status = open("error.txt", "a")
  status.write("There seems to be a problem on %s\n\n%s\n" % (local, str(type(err))))
  status.write("%s" % str(err.message))
  status.write("%s" % str(err.args))
  status.write("\n\n")
  status.close()