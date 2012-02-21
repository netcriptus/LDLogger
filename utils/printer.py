#!/usr/bin/env python
# encoding: utf-8


from datetime import datetime

class Printer(object):
  def __init__(self, output, version):
    self.output = open(output, "w")
    self.version = version
  
    
  def printVersion(self):
    self.output.write(self.version)
  
  
  def sessionTitle(self, title):
    self.output.write("\n\t#===== %s =====#\n\n" % title)
  
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
  
  
  def IEComponents(self, components_list):
    self.sessionTitle("IE Components")
    for IEComponent in components_list:
      self.output.write("Key: %s\n" % IEComponent["subkey"].decode("utf-8"))
      self.output.write("Object Name: %s\n" % IEComponent["objname"].decode("utf-8"))
      self.output.write("Path to executable: %s\n" % IEComponent["exepath"].decode("utf-8"))
      self.output.write("-"*50)
      self.output.write("\n")
  
  
  def IEToolbars(self, toolbars):
    if toolbars:
      self.sessionTitle("IE Toolbars")
      for toolbar in toolbars:
        self.output.write("Key: %s\n" % toolbar["subkey"].decode("utf-8"))
        self.output.write("Object Name: %s\n" % toolbar["objname"].decode("utf-8"))
        self.output.write("Path to executable: %s\n" % toolbar["exepath"].decode("utf-8"))
        self.output.write("-"*50)
        self.output.write("\n")
  
  
  def registers(self, regs):
    self.sessionTitle("Registry Keys")
    for reg in regs:
      self.output.write("%s\n" % reg.decode("utf-8"))
  
  
  def LSP(self, num_entries, LSPs):
    self.sessionTitle("LSP's")
    self.output.write("%d entradas\n\n" % num_entries)
    for LSP in LSPs:
      self.output.write("%s: %s\n" % (LSP[0].decode("utf-8"), LSP[1].decode("utf-8")))
  
  
  def DNS(self, primaryDNS, secondaryDNS):
    self.sessionTitle("DNS")
    if not primaryDNS:
      self.output.write("No network adapter found\n")
    else:
      self.output.write("Primary DNS: %s\nSecondary DNS: %s\n\n" % (primaryDNS, secondaryDNS))
  
  
  def autoruns(self, autoruns_list):
    if autoruns_list:
      self.sessionTitle("Autoruns found")
      for autorun in autoruns_list:
        self.output.write("Autorun found in %s\n" % autorun)
      self.output.write("\n\n")
  
  
  def mountpoints(self, suspect_mountpoints):
      if suspect_mountpoints:
        self.sessionTitle("Mountpoints")
        for mountpoint in suspect_mountpoints:
          self.output.write("%s - %s\n" % (mountpoint[0].decode("utf-8"), mountpoint[1].decode("utf-8")))
        self.output.write("\n\n")
  
  
  def services(self, svcs):
    self.sessionTitle("Services")
    if svcs:
      for svc in svcs:
        self.output.write(svc.decode("utf-8"))
        self.output.write("\n")
    else:
      self.output.write("Nothing unusual\n")
  
  
  def drivers(self, drvs):
    self.sessionTitle("Drivers")
    if drvs:
      for drv in drvs:
        self.output.write(drv.decode("utf-8"))
        self.output.write("\n")
    else:
      self.output.write("Nothing unusual\n")
    self.output.write("\n\n")
  
  
  def SVCHOST(self, anomalies):
    self.sessionTitle("SVCHOST")
    if len(anomalies) == 0:
      self.output.write("No anomalies were found\n")
    else:
      for anomalie in anomalies:
        self.output.write("%s -> %s\n" % (str(anomalie[0]), str(anomalie[1])))
  
  
  def safeboot(self, safeboot_exists):
    if safeboot_exists:
      self.sessionTitle("Safe Boot")
      self.output.write("Está máquina não pode entrar em modo seguro\n\n")
  
  
  def startups(self, global_startups, user_startups):
    if global_startups or user_startups:
      self.sessionTitle("Startups")
      if user_startups:
        self.output.write("Startups: ")
        for startup in user_startups:
          self.output.write("%s " % str(user_startups).strip().decode("utf-8"))
        self.output.write("\n")
      if global_startups:
        self.output.write("Global: ")
        for startup in global_startups:
          self.output.write("%s " % str(startup).strip().decode("utf-8"))
        self.output.write("\n")
  
  
  def winlogon(self, winlogon_entries):
    if winlogon_entries:
      self.sessionTitle("WinLogon")
      for entry in winlogon_entries:
        self.output.write("Notify: %s => %s\n" % (entry[0].decode("utf-8"), entry[1].decode("utf-8")))
  
  
  def IFEO(self, files):
    if files:
      self.sessionTitle("Image File Execution Options")
      for f in files:
        self.output.write("%s > %s\n" % (f[0].decode("utf-8"), f[1].decode("utf-8")))
      self.output.write("\n")
  
  
  def fileAssociation(self, misassociations):
    self.sessionTitle("File Association")
    if misassociations:
      for misassociation in misassociations:
        self.output.write("%s > %s\n" % (misassociation[0].decode("utf-8"), misassociation[1].decode("utf-8")))
    else:
      self.output.write("> ok\n")
  
  
  def finishLog(self):
    hour = datetime.now()
    self.output.write("*"*80)
    self.output.write("\nLog gerado ")
    self.output.write(" %02.d/%02.d/%02.d %02.d:%02.d:%02.d" % (hour.day, hour.month, hour.year, hour.hour, hour.minute, hour.second))
    self.output.write("\n\n*********************** Fim do log ***********************\n\n")
    self.output.close()
  