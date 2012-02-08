#!/usr/bin/env python
# encoding: utf-8
"""
regOps.py

Created by Fernando Cezar on 2011-12-02.
Copyright (c) 2011 __MyCompanyName__. All rights reserved.
"""
import _winreg


def discoverValues(key, subkey):
  """
  Given a key and a subkey, what are the values under this address?
  It returns a list of values, or None, if the key and/or subkey are not valid
  """
  try:
    key = getattr(_winreg, key)
    handle = _winreg.OpenKey(key, subkey)
    num_entries = _winreg.EnumValue(handle, 0)[-1]
    values = []
    for i in range(num_entries):
      try:
        values.append(_winreg.EnumValue(handle, i)[0])
      except WindowsError:
        continue
    return values
  except WindowsError:
    return None


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


def getRegs(reg_list):
  """
  Given a list with keys, subkeys and values, it returns the content of those
  registers in a list. Any error on key, subkey or value will be ignored
  """
  regs = []
  for reg_key in reg_list:
    values = reg_key["values"]
    if values == []:
      values = discoverValues(reg_key["key"], reg_key["subkey"])
      if not values:
        continue
      
    for value in values:
      try:
        content = getRegistryValue(reg_key["key"], reg_key["subkey"], value)
        if not content:
          content = "missing"
        regs.append(reg_key["key"] + chr(92) + reg_key["subkey"] + chr(92) + value + ": " + content)
      except WindowsError:
        continue
  return regs