#!/usr/bin/env python
# encoding: utf-8
"""
ldlogger.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "1.0 Beta"


def log_error(local, err):
  status = open("error.txt", "a")
  status.write("There seems to be a problem on %s\n\n%s\n" % (local, str(type(err))))
  status.write("%s" % str(err.message))
  status.write("%s" % str(err.args))
  status.write("\n\n")
  status.close()


try:
  import sys
  import subprocess
  from platform import win32_ver, architecture
  from lists import *
  from utils import regOps, processes, services, drivers, printer
  from datetime import datetime

  REG_KEYS = REG_KEYS_LIST.REG_KEYS
  BROWSERS = BROWSERS_LIST.BROWSERS
  svchost_whitelist = svchostWhitelist.svchost_whitelist
  winlogon_whitelist = winlogon_whitelist.winlogon_whitelist
  associations = associations.associations
  services_whitelist = srv_and_drvs_whitelist.services_whitelist
  drivers_whitelist = srv_and_drvs_whitelist.drivers_whitelist
  
except Exception as err:
  log_error("importing", err)

  
def main(argv):  
  output = printer.Printer("LDLogger.txt", VERSION)
  output.printVersion()
  
  try:
    # Getting OS name, build, service pack, and architecture
    OS, build, service_pack = win32_ver()[:-1]
    arch = architecture()[0]
  except Exception as err:
    log_error("platform use", err)
  
  try:
    # Getting used browsers and their versions
    browser_list = processes.getBrowsers(BROWSERS)
  except Exception as err:
    log_error("browsers", err)
  
  try:
    # Getting running processes and the path to its exetuable
    running_processes_list = []
    for process, process_path in processes.running_processes():
      running_processes_list.append("{0:30}  ==>  {1:30}\n".format(process.decode("utf-8"), process_path.decode("utf-8")))
  except Exception as err:
    log_error("running processes", err)
    
  try:
    # Getting Hosts file
    hosts = services.getHosts()
  except Exception as err:
    log_error("hosts", err)
  
  try:
    # Getting IE components
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEComponents = processes.getComponents(source_reg, target_reg)
  except Exception as err:
    log_error("IE components", err)
  
  try:
    # Getting IE toolbars
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Internet Explorer\Toolbar"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEToolbars = processes.getComponents(source_reg, target_reg, as_subkeys=False)
  except Exception as err:
    log_error("ie toolbars", err)
  
  try:
    # Getting some important keys in register
    regs = regOps.getRegs(REG_KEYS)
  except Exception as err:
    log_error("registry keys", err)
    
  try:
    # Getting LSP's
    num_entries, LSPs = services.getLSP()
  except Exception as err:
    log_error("LSP", err)
    
  try:
    # Getting DNS
    primaryDNS, secondaryDNS, adapterID = services.getDNS()
  except Exception as err:
    log_error("DNS", err)
  
  try:
    # Searching autoruns
    autoruns = drivers.searchAutorun()
  except Exception as err:
    log_error("autoruns", err)
  
  try:
    # Looking mountpoints
    suspect_mountpoints = drivers.getMountpoints()
  except Exception as err:
    log_error("mountpoints", err)
  
  try:
    # Getting Services
    svcs = drivers.getServices(services_whitelist)
  except Exception as err:
    log_error("services", err)
  
  try:
    # Getting Drivers
    drvs = drivers.getDrivers(drivers_whitelist)
  except Exception as err:
    log_error("drivers", err)
  
  try:
    # Searching for anomalies on svchost
    anomalies = services.getSvchostAnomalies(svchost_whitelist)
  except Exception as err:
    log_error("svchost", err)
  
  try:  
    # Discovering if safe boot exists
    safeboot = services.safeBootExists()
  except Exception as err:
    log_error("safe boot", err)
  
  try:
    # Getting startups:
    global_startups, user_startups = processes.getStartups()
  except Exception as err:
    log_error("startups", err)
  
  try:
    # Getting strange winlogon entries
    winlogon_entries = services.getWinlogonEntries(winlogon_whitelist)
  except Exception as err:
    log_error("winlogon", err)
  
  try:
    # Getting Image File Execution Options
    files = services.getImageFilesOptions()
  except Exception as err:
    log_error("image file execution", err)
  
  try:
    # Getting file extension association
    misassociations = services.checkAssociations(associations)
  except Exception as err:
    log_error("file association", err)
  
  
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
    log_error("write output", err)
    
  
  subprocess.call("start notepad LDLogger.txt", shell=True)
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))

