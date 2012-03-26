#!/usr/bin/env python
# encoding: iso8859-1

import regOps
import errorHandler
import commandHandler
import smartStr

def browser_version(browser_dict):
  try:
    version = regOps.getRegistryValue(browser_dict["key"], browser_dict["subkey"], "Version") or \
              regOps.getRegistryValue(browser_dict["key"], browser_dict["subkey"], "CurrentVersion")
  except WindowsError:
    version = None
  version = (browser_dict["name"], version)
  return version


def running_processes():
  processes_list = commandHandler.getOutput("wmic process get description,executablepath")
  if not processes_list:
    yield "This computer can't execute wmic"
  else:
    processes_list = processes_list.split("\n")[3:]
  
  for line in processes_list:
    parsed_line = smartStr.normalize(line.strip()).split(" ")
    if parsed_line:
      yield " ".join(parsed_line[1:]).strip()


def getStartups():
  user_startup_path = regOps.getRegistryValue("HKEY_CURRENT_USER",
                                               "Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\\", "Startup")
  global_startup_path = regOps.getRegistryValue("HKEY_LOCAL_MACHINE",
                                                 "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\\", "common startup")
  user_startups = commandHandler.getOutput(["dir", "/a/b", smartStr.normalize(user_startup_path)])
  user_startups = user_startups.split("\n")
  global_startups = commandHandler.getOutput(["dir", "/a/b", smartStr.normalize(global_startup_path)])
  global_startups = global_startups.split("\n")
  for startup in list(user_startups):
    if startup == "" or startup.strip().lower().endswith(".ini"):
      user_startups.remove(startup)
      
  for startup in list(global_startups):
    if startup == "" or startup.strip().lower().endswith(".ini"):
      global_startups.remove(startup)
      
  global_startups = global_startups
  user_startups = user_startups
  return global_startups, user_startups


def getBrowsers(BROWSERS):
  browser_list = []
  for browser_info in BROWSERS.values():
    new_browser = browser_version(browser_info)
    if new_browser:
      browser_list.append(new_browser)
  return browser_list


def getComponents(source_reg, target_reg, as_subkeys = True):
  components = []
  if as_subkeys:
    subkeys = regOps.discoverSubkeys(source_reg["key"], source_reg["subkey"])
  else:
    subkeys = regOps.discoverValues(source_reg["key"], source_reg["subkey"])
  if subkeys:
    for subkey in subkeys:
      subkey_name = subkey
      objname = regOps.getRegistryValue(source_reg["key"], source_reg["subkey"] + "\\" + subkey, "") or "no name"
      exepath = regOps.getRegistryValue(target_reg["key"], target_reg["subkey"] % subkey, "") or "file missing"
      components.append({"subkey": smartStr.normalize(subkey_name),
                        "objname": smartStr.normalize(objname),
                        "exepath": smartStr.normalize(exepath)})
  return components


