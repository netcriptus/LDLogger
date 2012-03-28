#!/usr/bin/env python
# encoding: iso8859-1
"""
ldlogger.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "1.4 Beta"

import sys
from platform import win32_ver, architecture
from lists import *
from utils import regOps, processes, services, drivers, printer, commandHandler, errorHandler, smartStr

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
  output = printer.Printer("LDLogger.txt", VERSION)
  output.printVersion()
  
  try:
    # Getting OS name, build, service pack, and architecture
    OS, build, service_pack = win32_ver()[:-1]
    arch = architecture()[0]
  except Exception as err:
    errorHandler.logError("platform use", err)
  
  try:
    # Getting used browsers and their versions
    browser_list = processes.getBrowsers(BROWSERS)
  except Exception as err:
    errorHandler.logError("browsers", err)
  
  try:
    # Getting running processes and the path to its exetuable
    running_processes_list = []
    for process_path in processes.running_processes():
      running_processes_list.append("%s\n" % process_path)
  except Exception as err:
    errorHandler.logError("running processes", err)
    
  try:
    # Getting Hosts file
    hosts = services.getHosts()
  except Exception as err:
    errorHandler.logError("hosts", err)
  
  try:
    # Getting IE components
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEComponents = processes.getComponents(source_reg, target_reg)
  except Exception as err:
    errorHandler.logError("IE components", err)
  
  try:
    # Getting IE toolbars
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Internet Explorer\Toolbar"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEToolbars = processes.getComponents(source_reg, target_reg, as_subkeys=False)
  except Exception as err:
    errorHandler.logError("ie toolbars", err)
  
  try:
    # Getting some important keys in register
    regs = regOps.getRegs(REG_KEYS)
  except Exception as err:
    errorHandler.logError("registry keys", err)
    
  try:
    # Getting LSP's
    num_entries, LSPs = services.getLSP()
  except Exception as err:
    errorHandler.logError("LSP", err)
    
  try:
    # Getting DNS
    primaryDNS, secondaryDNS, adapterID = services.getDNS()
  except Exception as err:
    errorHandler.logError("DNS", err)
  
  try:
    # Searching autoruns
    autoruns = drivers.searchAutorun()
  except Exception as err:
    errorHandler.logError("autoruns", err)
  
  try:
    # Looking mountpoints
    suspect_mountpoints = drivers.getMountpoints()
  except Exception as err:
    errorHandler.logError("mountpoints", err)
  
  try:
    # Getting Services
    svcs = drivers.getServices(services_whitelist)
  except Exception as err:
    errorHandler.logError("services", err)
  
  try:
    # Getting Drivers
    drvs = drivers.getDrivers(drivers_whitelist)
  except Exception as err:
    errorHandler.logError("drivers", err)
  
  try:
    # Searching for anomalies on svchost
    anomalies = services.getSvchostAnomalies(svchost_whitelist)
  except Exception as err:
    errorHandler.logError("svchost", err)
  
  try:  
    # Discovering if safe boot exists
    safeboot = services.safeBootExists()
  except Exception as err:
    errorHandler.logError("safe boot", err)
  
  try:
    # Getting startups:
    global_startups, user_startups = processes.getStartups()
  except Exception as err:
    errorHandler.logError("startups", err)
  
  try:
    # Getting strange winlogon entries
    winlogon_entries = services.getWinlogonEntries(winlogon_whitelist)
  except Exception as err:
    errorHandler.logError("winlogon", err)
  
  try:
    # Getting Image File Execution Options
    files = services.getImageFilesOptions()
  except Exception as err:
    errorHandler.logError("image file execution", err)
  
  try:
    # Getting file extension association
    misassociations = services.checkAssociations(associations)
  except Exception as err:
    errorHandler.logError("file association", err)
  
  
  try:
    # This is where we print the results we've got
    output.systemInfo(OS, build, service_pack, arch)
    output.browsers(browser_list)
    output.runningProcesses(running_processes_list)
    output.hosts(hosts)
    output.registers(regs, IEComponents, IEToolbars, global_startups, user_startups, LSPs, primaryDNS,
                     secondaryDNS, adapterID, winlogon_entries)
    output.autoruns(autoruns)
    output.mountpoints(suspect_mountpoints)
    output.services(svcs)
    output.drivers(drvs)
    output.SVCHOST(anomalies)
    output.safeboot(safeboot)
    output.IFEO(files)
    output.fileAssociation(misassociations)
    output.finishLog()
  except Exception as err:
    errorHandler.logError("write output", err)
    
  
  commandHandler.execute("start notepad LDLogger.txt")
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))

