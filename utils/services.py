#!/usr/bin/env python
# encoding: utf-8

import regOps
from os import getenv

def getSvchostAnomalies(whitelist):
  """
  Based on a whitelist, tries to detect weird entries on SVCHost.
  If something is detected, it searches for the injected DLL.
  """
  anomalies = []
  values = regOps.getRegistryValue("HKEY_LOCAL_MACHINE", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost", "netsvcs")
  for value in values:
    if value not in whitelist:
      DLL = regOps.getRegistryValue("HKEY_LOCAL_MACHINE", "SYSTEM\CurrentControlSet\Services\\" +  value + "\\Parameters", "ServiceDll")
      if not DLL:
        DLL = "Unknown. You may need to restart the system."
      anomalies.append((value, DLL))
      
  return anomalies


def safeBootExists():
  safe_boot_regs = regOps.discoverSubkeys("HKEY_LOCAL_MACHINE", "SYSTEM\CurrentControlSet\Control\SafeBoot")
  if len(safe_boot_regs) == 0:
    return False
  else:
    return True


def getLSP():
  num_entries = regOps.getRegistryValue("HKEY_LOCAL_MACHINE",
                                        "SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
                                        "Num_Catalog_Entries")
                                        
  folders = regOps.discoverSubkeys("HKEY_LOCAL_MACHINE",
                                   "SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries")
                                   
  lsp_list = []
  for folder in folders:
    folder_num = int(folder)
    folder_path = regOps.getRegistryValue("HKEY_LOCAL_MACHINE",
                  "SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\%s" % folder,
                  "PackedCatalogItem")
    folder_path = folder_path.split(".dll")[0] + ".dll"
    lsp_list.append(("Arquivo %s" % folder_num, folder_path))
  return num_entries, lsp_list


def getOutcastKeys(key, subkey, whitelist):
  outcasts = []
  entries = regOps.discoverSubkeys(key, subkey) or []
  for entry in entries:
    if entry not in whitelist:
      outcasts.append(entry)
  return outcasts


def getWinlogonEntries(whitelist):
  key = "HKEY_LOCAL_MACHINE"
  subkey = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
  outcasts = getOutcastKeys(key, subkey, whitelist)
  suspect_entries = []
  for outcast in outcasts:
    entry_path = regOps.getRegistryValue("HKEY_LOCAL_MACHINE",
                                        "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\%s" % outcast,
                                       "  DLLName")
    if outcast and entry_path:
      suspect_entries.append((outcast, entry_path))
      
  return suspect_entries


def checkAssociations(associations):
  anomalies = []
  for full_key in associations.keys():
    key = full_key.split("\\")[0]
    subkey = "\\".join(full_key.split("\\")[1:])
    expected_value = associations[full_key]
    value = regOps.getRegistryValue(key, subkey, "")
    if value != expected_value:
      anomalies.append((subkey, value))
      
  return anomalies


def getDNS():
  key = "HKEY_LOCAL_MACHINE"
  path_to_adapter = "SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
  partial_path = regOps.discoverSubkeys(key, path_to_adapter)
  for subkey in partial_path:
    if subkey.startswith("{"):
      adapterID = subkey
      break
  else:
    return None, None
    
  DNS = regOps.getRegistryValue(key, "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % adapterID, "DhcpNameServer")
  if DNS and len(DNS.split(" ")) == 2:
    primary_dns = DNS.split(" ")[0]
    secondary_dns = DNS.split(" ")[1]
  else:
    primary_dns = DNS
    secondary_dns = ""
    
  return primary_dns, secondary_dns
  


def getImageFilesOptions():
  key = "HKEY_LOCAL_MACHINE"
  IFEO = "Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
  subkeys = regOps.discoverSubkeys(key, IFEO)
  suspects = []
  for subkey in subkeys:
    debugger = regOps.getRegistryValue(key, IFEO + "\\" + subkey, "Debugger")
    if debugger and subkey.strip() != "Your Image File Name Here without a path":
      suspects.append([subkey, debugger])
  return suspects or None


def getHosts():
  try:
    fp = open(getenv("WINDIR") + "\System32\drivers\etc\hosts")
  except IOError:
    return ["Arquivo Hosts não existe em " + getenv("WINDIR") + "\System32\drivers\etc\hosts"]
  lines = fp.readlines()
  fp.close()
    
  for line in list(lines):
    if line.startswith("#") or line.startswith("\n"):
      lines.remove(line)
      
  return lines
