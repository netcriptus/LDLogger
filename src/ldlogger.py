#!/usr/bin/env python
# encoding: utf-8
"""
ldlogger.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "0.1 alpha"


import sys
import subprocess
from platform import win32_ver, architecture
from lists import *
from utils import regOps, processes, services
from datetime import datetime

REG_KEYS = REG_KEYS_LIST.REG_KEYS
BROWSERS = BROWSERS_LIST.BROWSERS
svchost_whitelist = svchostWhitelist.svchost_whitelist
winlogon_whitelist = winlogon_whitelist.winlogon_whitelist
image_options_whitelist = image_options_whitelist.image_options_whitelist
associations = associations.associations

def main(argv):  
  #output = sys.stdout
  output = open("LDLogger.txt", "w")
  
  output.write("LDLogger Version %s\n\n" % VERSION)
  
  # Getting OS name, build, service pack, and architecture
  OS, build, service_pack = win32_ver()[:-1]
  arch = architecture()[0]
  output.write("\n\t#===== System =====#\n\n")
  output.write("SO: %s Build: %s\n" % (OS, build))
  output.write("Service Pack %s Arquitetura: %s\n" % (service_pack, arch))
  
  # Getting used browsers and their versions
  browser_list = processes.getBrowsers(BROWSERS)
  output.write("\n\t#===== BROWSERS =====#\n\n")
  for browser in browser_list:
    if browser[1]:
      output.write("%s => %s\n" % (browser[0], browser[1]))
  
  # Getting running processes and the path to its exetuable
  output.write("\n\t#===== Running Processes =====#\n\n")
  for process, process_path in processes.running_processes():
    output.write("%s\t=>\t%s\n" % (process, process_path))
    
  # Getting some important keys in register
  output.write("\n\t#===== Registry Keys =====#\n\n")
  regs = regOps.getRegs(REG_KEYS)
  for reg in regs:
    output.write("%s\n" % reg)
  
  # Searching for anomalies on svchost
  output.write("\n\t#===== SVCHOST =====#\n\n")
  anomalies = services.getSvchostAnomalies(svchost_whitelist)
  output.write(str(anomalies))
  output.write("\n\n")
  if len(anomalies) == 0:
    output.write("No anomalies were found\n")
  else:
    for anomalie in anomalies:
      output.write("%s\n" % anomalie)
    
  # Discovering if safe boot exists
  if not services.safeBootExists():
    output.write("\n\t#===== Safe Boot =====#\n\n")
    output.write("Está máquina não pode entrar em modo seguro\n\n")
    
  # Getting Hosts file
  hosts = services.getHosts()
  output.write("\n\t#===== HOSTS =====#\n\n")
  for host in hosts[:15]:
    output.write("%s\n" % host.strip())
  if len(hosts) > 15:
    output.write("E mais %d entradas\n" % len(hosts) - 15)
    
  # Getting IE components
  output.write("\n\t#===== IE Components =====#\n\n")
  source_reg = {"key": "HKEY_LOCAL_MACHINE",
                "subkey": "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"}
  target_reg = {"key": "HKEY_CLASSES_ROOT",
                "subkey": "CLSID\%s\InprocServer32"}
  IEComponents = processes.getComponents(source_reg, target_reg)
  for IEComponent in IEComponents:
    output.write("Key: %s\n" % IEComponent["subkey"])
    output.write("Object Name: %s\n" % IEComponent["objname"])
    output.write("Path to executable: %s\n" % IEComponent["exepath"])
    output.write("-"*50)
    output.write("\n")
    
  # Getting IE toolbars
  source_reg = {"key": "HKEY_LOCAL_MACHINE",
                "subkey": "SOFTWARE\Microsoft\Internet Explorer\Toolbar"}
  target_reg = {"key": "HKEY_CLASSES_ROOT",
                "subkey": "CLSID\%s\InprocServer32"}
  IEToolbars = processes.getComponents(source_reg, target_reg, as_subkeys=False)
  if IEToolbars:
    output.write("\n\t#===== IE Toolbars =====#\n\n")
    for toolbar in IEToolbars:
      output.write("Key: %s\n" % toolbar["subkey"])
      output.write("Object Name: %s\n" % toolbar["objname"])
      output.write("Path to executable: %s\n" % toolbar["exepath"])
      output.write("-"*50)
      output.write("\n")
    
  # Getting startups:
  global_startups, user_startups = processes.getStartups()
  if global_startups or user_startups:
    output.write("\n\t#===== Startups =====#\n\n")
    if user_startups:
      output.write("Startups: ")
      for startup in user_startup:
        output.write("%s " % user_startups)
      output.write("\n")
    if global_startups:
      output.write("Global: ")
      for startup in global_startups:
        output.write("%s " % startup)
      output.write("\n")
    
  # Getting LSP's
  output.write("\n\t#===== LSP's =====#\n\n")
  num_entries, LSPs = services.getLSP()
  output.write("%d entradas\n\n" % num_entries)
  for LSP in LSPs:
    output.write("%s: %s\n" % (LSP[0], LSP[1]))
  
  # Getting strange winlogon entries
  winlogon_entries = services.getWinlogonEntries(winlogon_whitelist)
  if winlogon_entries:
    output.write("\n\t#===== WinLogon =====#\n\n")
    for entry in winlogon_entries:
      output.write("Notify: %s => %s\n" % (entry[0], entry[1]))
    
  # Getting Image File Execution Options
  output.write("\n\t#===== Image File Execution Options =====#\n\n")
  files = services.getImageFilesOptions(image_options_whitelist)
  for f in files:
    output.write("%s\n" % f)
  output.write("\n")
  
  # Getting file extension association
  misassociations = services.checkAssociations(associations)
  output.write("\n\t#===== File Association =====#\n\n")
  if misassociations:
    for misassociation in misassociations:
      output.write("%s > %s\n" % (misassociation[0], misassociation[1]))
  else:
    output.write("> ok\n")
    
  # Getting DNS
  output.write("\n\t#===== DNS =====#\n\n")
  primaryDNS, secondaryDNS = services.getDNS()
  if not primaryDNS:
    output.write("No network adapter found\n")
  else:
    output.write("Primary DNS: %s\nSecondary DNS: %s\n\n" % (primaryDNS, secondaryDNS))
    
  svcs = processes.getServices()
  output.write("\n\t#===== Services =====#\n\n")
  output.write(svcs)
  
  drivers = processes.getDrivers()
  output.write("\n\t#===== Drivers =====#\n\n")
  output.write(drivers)
  output.write("\n\n")
  
  hour = datetime.now()
  output.write("*"*80)
  output.write("\nLog gerado ")
  output.write(" %02.d/%02.d/%02.d %02.d:%02.d:%02.d" % (hour.day, hour.month, hour.year, hour.hour, hour.minute, hour.second))
  output.write("\n\n*********************** Fim do log ***********************\n\n")
  output.close()
  return 0


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv))
  except Exception as err:
    error = open("error.txt", "w")
    error.write("%s\n" % str(type(err)))
    error.write("%s\n" % str(err.message))
    error.write("%s\n" % str(err.args))
    error.close()
    sys.exit(1)

