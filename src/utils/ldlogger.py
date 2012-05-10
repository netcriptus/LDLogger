#!/usr/bin/env python
# encoding: iso8859-1
"""
ldlogger.py

Created by Urlan Barros on 2012-04-18.
Copyright (c) 2012 __8bitsweb__. All rights reserved.
"""

import sys
from platform import win32_ver, architecture
from lists import *
from utils import regOps, processes, services, drivers, printer, commandHandler, errorHandler, smartStr

  # Getting used browsers and their versions
  def getBrowsersList(self, lists):
    try:
      browsers_list = processes.getBrowsers(lists["BROWSERS"])
      return browsers_list
    except Exception as err:
      errorHandler.logError("navegadores", err)

  # Getting running processes and the path to its executable
  def getRunningProcessesList(self):
    try:
      running_processes_list = []
      for process_path in processes.running_processes():
        running_processes_list.append("%s\n" % process_path)
      return running_processes_list
    except Exception as err:
      errorHandler.logError("running processes", err)

  # Getting Hosts file
  def getHostsFile(self):
    try:
      hosts = services.getHosts()
      return hosts
    except Exception as err:
      errorHandler.logError("hosts", err)

  # Getting IE components
  def getIEComponents(self):
    try:
      source_reg = {"key": "HKEY_LOCAL_MACHINE",
                    "subkey": "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"}
      target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
      IEComponents = processes.getComponents(source_reg, target_reg)
      return IEComponents
    except Exception as err:
      errorHandler.logError("IE components", err)

  # Getting IE toolbars
  def getIEToolbars(self):
    try:
      source_reg = {"key": "HKEY_LOCAL_MACHINE",
                    "subkey": "SOFTWARE\Microsoft\Internet Explorer\Toolbar"}
      target_reg = {"key": "HKEY_CLASSES_ROOT",
                    "subkey": "CLSID\%s\InprocServer32"}
      IEToolbars = processes.getComponents(source_reg, target_reg, as_subkeys=False)
      return IEToolbars
    except Exception as err:
      errorHandler.logError("IE toolbars", err)


  # Getting some important keys in register
  def getKeysFromRegister(self, lists):
    try:
      regs = regOps.getRegs(lists["REG_KEYS"])
      return regs
    except Exception as err:
      errorHandler.logError("registry keys", err)

  # Searching autoruns
  def getAutoruns(self):
    try:
      autoruns = drivers.searchAutorun()
      return autoruns
    except Exception as err:
      errorHandler.logError("autoruns", err)

  #Looking mountpoints
  def getMountpoints(self):
    try:
      suspect_mountpoints = drivers.getMountpoints()
      return suspect_mountpoints
    except Exception as err:
      errorHandler.logError("mountpoints", err)

  # Getting Services
  def getServices(self, lists):
    try:
      svcs = drivers.getServices(lists["services_whitelist"])
      return svcs
    except Exception as err:
      errorHandler.logError("services", err)

  # Getting Drivers
  def getDrivers(self, lists):
    try:
      drvs = drivers.getDrivers(lists["drivers_whitelist"])
      return drvs
    except Exception as err:
      errorHandler.logError("drivers", err)


  # Searching for anomalies on svchost
  def searchForAnomaliesOnSvchost(self, lists):
    try:
      anomalies = services.getSvchostAnomalies(lists["svchost_whitelist"])
      return anomalies
    except Exception as err:
      errorHandler.logError("svchost", err)

  # Discovering if safe boot exists
  def discoveringSafeBoot(self):
    try:
      safeboot = services.safeBootExists()
      return safeboot
    except Exception as err:
      errorHandler.logError("safe boot", err)

  # Getting strange winlogon entries
  def getWinlogonEntries(self, lists):
    try:
      winlogon_entries = services.getWinlogonEntries(lists["winlogon_whitelist"])
      return winlogon_entries
    except Exception as err:
      errorHandler.logError("winlogon", err)

  # Getting Image File Execution Options
  def getImageFilesOptions(self):
    try:
      files = services.getImageFilesOptions()
      return files
    except Exception as err:
      errorHandler.logError("image file execution", err)

  # Getting file extension association
  def checkAssociations(self, lists):
    try:
      misassociations = services.checkAssociations(lists["associations"])
      return misassociations
    except Exception as err:
      errorHandler.logError("file association", err)

  # Executing LDLogger
  def executeLDLogger(self, lists):  
    try:
      # Getting OS name, build, service pack, and architecture
      OS, build, service_pack = win32_ver()[:-1]
      arch = architecture()[0]
    except Exception as err:
      errorHandler.logError("platform use", err)
  
    browser_list = self.getBrowsersList(lists)

    running_processes_list = []
    running_processes_list = self.getRunningProcessesList()
    
    hosts = self.getHostsFile()
  
    IEComponents = self.getIEComponents()
    IEToolbars = self.getIEToolbars()

    regs = self.getKeysFromRegister(lists)

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
    
    autoruns = self.getAutoruns()

    suspect_mountpoints = self.getMountpoints()

    svcs = self.getServices(lists)

    drvs = self.getDrivers(lists)
    
    anomalies = self.searchForAnomaliesOnSvchost(lists)
    
    safeboot = self.discoveringSafeBoot()
    
    try:
      # Getting startups:
      global_startups, user_startups = processes.getStartups()
    except Exception as err:
      errorHandler.logError("startups", err)
  
    winlogon_entries = self.getWinlogonEntries(lists)
  
    files_options = self.getImageFilesOptions()
  
    misassociations = self.checkAssociations(lists)

    output = printer.Printer("LDLogger.txt", self.version)
    output.printVersion()  
  
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
      output.IFEO(files_options)
      output.fileAssociation(misassociations)
      output.finishLog()
    except Exception as err:
      errorHandler.logError("write output", err)
