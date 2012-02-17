#!/usr/bin/env python
# encoding: utf-8
"""
ldlogger.py

Created by Fernando Cezar on 2011-11-30.
Copyright (c) 2011 __8bitsweb__. All rights reserved.
"""

VERSION = "0.2.2 alpha"


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
  from utils import regOps, processes, services, drivers
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
  #output = sys.stdout
  output = open("LDLogger.txt", "w")
  
  output.write("LDLogger Version %s\n\n" % VERSION)
  
  try:
    # Getting OS name, build, service pack, and architecture
    OS, build, service_pack = win32_ver()[:-1]
    arch = architecture()[0]
    output.write("\n\t#===== System =====#\n\n")
    output.write("SO: %s Build: %s\n" % (OS, build))
    output.write("Service Pack %s Arquitetura: %s\n" % (service_pack, arch))
  except Exception as err:
    log_error("platform use", err)
  
  try:
    # Getting used browsers and their versions
    browser_list = processes.getBrowsers(BROWSERS)
    output.write("\n\t#===== BROWSERS =====#\n\n")
    for browser in browser_list:
      if browser[1]:
        output.write("%s => %s\n" % (browser[0], browser[1]))
  except Exception as err:
    log_error("browsers", err)
  
  try:
    # Getting running processes and the path to its exetuable
    output.write("\n\t#===== Running Processes =====#\n\n")
    for process, process_path in processes.running_processes():
      output.write("{0:30}  ==>  {1:30}\n".format(process.decode("utf-8"), process_path.decode("utf-8")))
  except Exception as err:
    log_error("running processes", err)
  
  try:
    # Getting some important keys in register
    output.write("\n\t#===== Registry Keys =====#\n\n")
    regs = regOps.getRegs(REG_KEYS)
    for reg in regs:
      output.write("%s\n" % reg.decode("utf-8"))
  except Exception as err:
    log_error("registry keys", err)
  
  try:
    # Searching for anomalies on svchost
    output.write("\n\t#===== SVCHOST =====#\n\n")
    anomalies = services.getSvchostAnomalies(svchost_whitelist)
    if len(anomalies) == 0:
      output.write("No anomalies were found\n")
    else:
      for anomalie in anomalies:
        output.write("%s -> %s\n" % (str(anomalie[0]), str(anomalie[1])))
  except Exception as err:
    log_error("svchost", err)
  
  try:  
    # Discovering if safe boot exists
    if not services.safeBootExists():
      output.write("\n\t#===== Safe Boot =====#\n\n")
      output.write("Está máquina não pode entrar em modo seguro\n\n")
  except Exception as err:
    log_error("safe boot", err)
  
  try:
    # Getting Hosts file
    hosts = services.getHosts()
    output.write("\n\t#===== HOSTS =====#\n\n")
    for host in hosts[:15]:
      output.write("%s\n" % host.strip())
    if len(hosts) > 15:
      output.write("E mais %d entradas\n" % len(hosts) - 15)
  except Exception as err:
    log_error("hosts", err)
  
  try:
    # Getting IE components
    output.write("\n\t#===== IE Components =====#\n\n")
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEComponents = processes.getComponents(source_reg, target_reg)
    for IEComponent in IEComponents:
      output.write("Key: %s\n" % IEComponent["subkey"].decode("utf-8"))
      output.write("Object Name: %s\n" % IEComponent["objname"].decode("utf-8"))
      output.write("Path to executable: %s\n" % IEComponent["exepath"].decode("utf-8"))
      output.write("-"*50)
      output.write("\n")
  except Exception as err:
    log_error("IE components", err)
  
  try:
    # Getting IE toolbars
    source_reg = {"key": "HKEY_LOCAL_MACHINE",
                  "subkey": "SOFTWARE\Microsoft\Internet Explorer\Toolbar"}
    target_reg = {"key": "HKEY_CLASSES_ROOT",
                  "subkey": "CLSID\%s\InprocServer32"}
    IEToolbars = processes.getComponents(source_reg, target_reg, as_subkeys=False)
    if IEToolbars:
      output.write("\n\t#===== IE Toolbars =====#\n\n")
      for toolbar in IEToolbars:
        output.write("Key: %s\n" % toolbar["subkey"].decode("utf-8"))
        output.write("Object Name: %s\n" % toolbar["objname"].decode("utf-8"))
        output.write("Path to executable: %s\n" % toolbar["exepath"].decode("utf-8"))
        output.write("-"*50)
        output.write("\n")
  except Exception as err:
    log_error("ie toolbars", err)
  
  try:
    # Getting startups:
    global_startups, user_startups = processes.getStartups()
    if global_startups or user_startups:
      output.write("\n\t#===== Startups =====#\n\n")
      if user_startups:
        output.write("Startups: ")
        for startup in user_startups:
          output.write("%s " % str(user_startups).decode("utf-8"))
        output.write("\n")
      if global_startups:
        output.write("Global: ")
        for startup in global_startups:
          output.write("%s " % str(startup).decode("utf-8"))
        output.write("\n")
  except Exception as err:
    log_error("startups", err)
  
  try:
    # Getting LSP's
    output.write("\n\t#===== LSP's =====#\n\n")
    num_entries, LSPs = services.getLSP()
    output.write("%d entradas\n\n" % num_entries)
    for LSP in LSPs:
      output.write("%s: %s\n" % (LSP[0].decode("utf-8"), LSP[1].decode("utf-8")))
  except Exception as err:
    log_error("LSP", err)
  
  try:
    # Getting strange winlogon entries
    winlogon_entries = services.getWinlogonEntries(winlogon_whitelist)
    if winlogon_entries:
      output.write("\n\t#===== WinLogon =====#\n\n")
      for entry in winlogon_entries:
        output.write("Notify: %s => %s\n" % (entry[0].decode("utf-8"), entry[1].decode("utf-8")))
  except Exception as err:
    log_error("winlogon", err)
  
  try:
    # Getting Image File Execution Options
    files = services.getImageFilesOptions()
    if files:
      output.write("\n\t#===== Image File Execution Options =====#\n\n")
      for f in files:
        output.write("%s > %s\n" % (f[0].decode("utf-8"), f[1].decode("utf-8")))
      output.write("\n")
  except Exception as err:
    log_error("image file execution", err)
  
  try:
    # Getting file extension association
    misassociations = services.checkAssociations(associations)
    output.write("\n\t#===== File Association =====#\n\n")
    if misassociations:
      for misassociation in misassociations:
        output.write("%s > %s\n" % (misassociation[0].decode("utf-8"), misassociation[1].decode("utf-8")))
    else:
      output.write("> ok\n")
  except Exception as err:
    log_error("file association", err)
  
  try:
    # Getting DNS
    output.write("\n\t#===== DNS =====#\n\n")
    primaryDNS, secondaryDNS = services.getDNS()
    if not primaryDNS:
      output.write("No network adapter found\n")
    else:
      output.write("Primary DNS: %s\nSecondary DNS: %s\n\n" % (primaryDNS, secondaryDNS))
  except Exception as err:
    log_error("DNS", err)
    
  try:
    # Getting Services
    svcs = drivers.getServices(services_whitelist)
    output.write("\n\t#===== Services =====#\n\n")
    if svcs:
      for svc in svcs:
        output.write(svc.decode("utf-8"))
        output.write("\n")
    else:
      output.write("Nothing unusual\n")
  except Exception as err:
    log_error("services", err)
  
  try:
    # Getting Drivers
    drvs = drivers.getDrivers(drivers_whitelist)
    output.write("\n\t#===== Drivers =====#\n\n")
    if drvs:
      for drv in drvs:
        output.write(drv.decode("utf-8"))
        output.write("\n")
    else:
      output.write("Nothing unusual\n")
    output.write("\n\n")
  except Exception as err:
    log_error("drivers", err)
    
  try:
    # Searching autoruns
    autoruns = drivers.searchAutorun()
    if autoruns:
      output.write("\n\t#===== Autoruns found =====#\n\n")
      for autorun in autoruns:
        output.write("Autorun found in %s\n" % autorun)
      output.write("\n\n")
  except Exception as err:
    log_error("autoruns", err)
    
  try:
    # Looking mountpoints
    suspect_mountpoints = drivers.getMountpoints()
    if suspect_mountpoints:
      output.write("\n\t#===== Mountpoints =====#\n\n")
      for mountpoint in suspect_mountpoints:
        output.write("%s - %s\n" % (mountpoint[0].decode("utf-8"), mountpoint[1].decode("utf-8")))
      output.write("\n\n")
      
  except Exception as err:
    log_error("mountpoints", err)
  
  hour = datetime.now()
  output.write("*"*80)
  output.write("\nLog gerado ")
  output.write(" %02.d/%02.d/%02.d %02.d:%02.d:%02.d" % (hour.day, hour.month, hour.year, hour.hour, hour.minute, hour.second))
  output.write("\n\n*********************** Fim do log ***********************\n\n")
  output.close()
  subprocess.call("start notepad LDLogger.txt", shell=True)
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))

