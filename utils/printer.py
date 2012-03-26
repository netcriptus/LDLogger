#!/usr/bin/env python
# encoding: iso8859-1


from datetime import datetime
import smartStr

class Printer(object):
  def __init__(self, output, version):
    self.output = open(output, "w")
    self.version = version
  
    
  def printVersion(self):
    self.output.write("LDLogger Versão ")
    self.output.write(self.version)
    self.output.write(" - Lain Experiment")
    self.output.write("\n")
    self.output.write("http://www.linhadefensiva.org/ldlogger/")
    self.output.write("\n")
  
  
  def sessionTitle(self, title):
    self.output.write("\n#===== %s =====#\n\n" % title)
  
  def systemInfo(self, OS, build, service_pack, arch):
    self.sessionTitle("System")
    self.output.write("SO: %s Build: %s\n" % (OS, build))
    self.output.write("Service Pack %s Arquitetura: %s\n" % (service_pack, arch))
  
  
  def browsers(self, browser_list):
    self.sessionTitle("BROWSERS")
    for browser in browser_list:
      if browser[1]:
        self.output.write("%s => %s\n" % (browser[0], browser[1]))
  
  
  def runningProcesses(self, processes_list):
    self.sessionTitle("Running Processes")
    for process in processes_list:
      self.output.write(process)
  
  
  def hosts(self, hosts_file):
    self.sessionTitle("HOSTS")
    for host in hosts_file[:15]:
      self.output.write("%s\n" % host.strip())
    if len(hosts_file) > 15:
      self.output.write("E mais %d entradas\n" % len(hosts) - 15)
  
  
  def BHO(self, components_list):
    for IEComponent in components_list:
      self.output.write("BHO - %s - "  % smartStr.normalize(IEComponent["objname"]))
      self.output.write("%s - " % smartStr.normalize(IEComponent["subkey"]))
      self.output.write("%s\n" % smartStr.normalize(IEComponent["exepath"]))
  
  
  def IEToolbars(self, toolbars):
    if toolbars:
      for toolbar in toolbars:
        self.output.write("Toolbar - %s - " % smartStr.normalize(toolbar["objname"]))
        self.output.write("%s - " % smartStr.normalize(toolbar["subkey"]))
        self.output.write("%s\n" % smartStr.normalize(toolbar["exepath"]))
  
  
  def registers(self, regs, IEComponents, IEToolbars, global_startups, user_startups,
                LSPs, primaryDNS, secondaryDNS, adapterID, winlogon_entries):
    self.sessionTitle("Registry Keys")
    self.BHO(IEComponents)
    self.IEToolbars(IEToolbars)
    for reg in regs:
      if reg == "Startups":
        self.startups(global_startups, user_startups)
        continue
      elif reg == "winlogon":
        self.LSP(LSPs)
        self.DNS(primaryDNS, secondaryDNS, adapterID)
        self.winlogon(winlogon_entries)
        continue
      self.output.write("%s\n" % reg)
  
  
  def LSP(self, LSPs):
    for LSP in LSPs:
      self.output.write("LSP - %s: %s\n" % (smartStr.normalize(LSP[0]), smartStr.normalize(LSP[1])))
  
  
  def DNS(self, primaryDNS, secondaryDNS, adapterID):
    if not primaryDNS:
      self.output.write("No network adapter found\n")
    else:
      self.output.write("TCPIP - %s - NAMESERVER: %s, %s\n" % (adapterID, primaryDNS, secondaryDNS))
  
  
  def autoruns(self, autoruns_list):
    if autoruns_list:
      for autorun in autoruns_list:
        self.output.write("Autorun: %s\\ Autorun present!\n" % autorun)
      self.output.write("\n\n")
  
  
  def mountpoints(self, suspect_mountpoints):
      if suspect_mountpoints:
        for mountpoint in suspect_mountpoints:
          self.output.write("MountPoints2: %s - %s\n" % (mountpoint[0], mountpoint[1]))
  
  
  def services(self, svcs):
    self.sessionTitle("Services")
    if svcs:
      for svc in svcs:
        self.output.write(svc)
        self.output.write("\n")
    else:
      self.output.write("Nothing unusual\n")
  
  
  def drivers(self, drvs):
    self.sessionTitle("Drivers")
    if drvs:
      for drv in drvs:
        self.output.write(drv)
        self.output.write("\n")
    else:
      self.output.write("Nothing unusual\n")
    self.output.write("\n\n")
  
  
  def SVCHOST(self, anomalies):
    if len(anomalies) == 0:
      self.output.write("NetSvc: No anomalies were found\n\n")
    else:
      for anomalie in anomalies:
        self.output.write("NetSvc: {0} - {1}\n".format(str(anomalie[0]), str(anomalie[1])))
  
  
  def safeboot(self, safeboot_exists):
    if not safeboot_exists:
      self.output.write("Safeboot: Esta máquina não pode entrar em modo seguro\n\n")
  
  
  def startups(self, global_startups, user_startups):
    if user_startups:
      self.output.write("Startups: ")
      for startup in user_startups:
        self.output.write("%s " % smartStr.normalize(str(user_startups)).strip())
      self.output.write("\n")
    if global_startups:
      self.output.write("Global: ")
      for startup in global_startups:
        self.output.write("%s " % smartStr.normalize(str(startup)).strip())
      self.output.write("\n")
  
  
  def winlogon(self, winlogon_entries):
    if winlogon_entries:
      for entry in winlogon_entries:
        self.output.write("Notify: %s => %s\n" % (entry[0], entry[1]))
  
  
  def IFEO(self, files):
    if files:
      for f in files:
        self.output.write("IFEO - {0}: Debugger={1}\n".format(f[0], f[1]))
      self.output.write("\n")
  
  
  def fileAssociation(self, misassociations):
    self.sessionTitle("File Association")
    if misassociations:
      for misassociation in misassociations:
        self.output.write("HKLM\..\%s: %s\n" % (misassociation[0], misassociation[1]))
      self.output.write("\n")
    else:
      self.output.write("> ok\n")
  
  
  def finishLog(self):
    hour = datetime.now()
    self.output.write("\n\n")
    self.output.write("*"*80)
    self.output.write("\nLog gerado ")
    self.output.write(" %02.d/%02.d/%02.d %02.d:%02.d:%02.d" % (hour.day, hour.month, hour.year, hour.hour, hour.minute, hour.second))
    self.output.write("\n\n*********************** Fim do log ***********************\n\n")
    self.output.close()
  
