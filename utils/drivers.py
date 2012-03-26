#!/usr/bin/env python
# encoding: iso8859-1

import regOps
import errorHandler
import commandHandler
import smartStr
from win32api import GetFileVersionInfo, GetLogicalDriveStrings
from win32file import GetDriveType, DRIVE_FIXED
from os import getenv


def getCompanyName(image_path):
  if image_path.startswith("%"):
    filename = getenv(image_path.split("%")[1].upper()) + "\\" + image_path.split("%")[-1]
  elif image_path.startswith("\\SystemRoot"):
    filename = image_path.replace("\\SystemRoot", getenv("SYSTEMROOT"))
  elif image_path.startswith("C:") or image_path.startswith("\"C:"):
    filename = image_path
  else:
    filename = getenv("SYSTEMROOT") + "\\" + image_path
    
  if " -" in filename:
    filename = filename.split(" -")[0]
  if not "." in filename:
    filename = filename + ".exe"
    
  try:
    lang, codepage = GetFileVersionInfo(filename, '\\VarFileInfo\\Translation')[0]
  except:
    return "Unknown"
  strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, "CompanyName")
  return GetFileVersionInfo(filename, strInfoPath)


def parseSC(query_type, raw_info, whitelist):
  parsed_sc = []
  for line in raw_info.split("\n"):
    if line.startswith("SERVICE"):
      service_name = " ".join(line.strip().split(" ")[1:])
      if service_name in whitelist:
        continue
      display_name = regOps.getRegistryValue("HKEY_LOCAL_MACHINE", "SYSTEM\CurrentControlSet\Services\%s" % service_name, "DisplayName")
      image_path = regOps.getRegistryValue("HKEY_LOCAL_MACHINE", "SYSTEM\CurrentControlSet\Services\%s" % service_name, "ImagePath")
      if display_name and image_path:
        company_name = getCompanyName(image_path)
      else:
        display_name, image_path, company_name = ("unknown", "unknown", "unknown")
    elif line.strip().startswith("STATE"):
      if service_name in whitelist:
        continue
      state = line.strip().split(" ")[-1]
      query_type = smartStr.normalize(query_type)
      display_name = smartStr.normalize(display_name)
      service_name = smartStr.normalize(service_name)
      company_name = smartStr.normalize(company_name)
      image_path = smartStr.normalize(image_path)
      parsed_sc.append("%s - %s (%s) - %s - %s" % (query_type, display_name, service_name, company_name, image_path))
  return parsed_sc


def getServices(whitelist):
  try:
    serv = commandHandler.getOutput("sc query type= service")
  except Exception as err:
    errorHandler.logError("sc calling\nThis computer can't execute sc", err)
    return ["Este computador não executa o comando sc. Impossível descobrir serviços."]
  serv = parseSC("SRV", serv, whitelist)
  return serv


def getDrivers(whitelist):
  try:
    drvs = commandHandler.getOutput("sc query type= driver")
  except Exception as err:
    errorHandler.logError("sc calling\nThis computer can't execute sc", err)
    return ["Este computador não executa o comando sc. Impossível descobrir drivers."]
  drvs = parseSC("DRV", drvs, whitelist)
  return drvs


def getMountpoints():
  suspects = []
  main_key = "HKEY_CURRENT_USER"
  subkey = "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\%s\shell\%s\command"
  mountpoints = regOps.discoverSubkeys("HKEY_CURRENT_USER", "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2")
  for mountpoint in mountpoints:
    value = regOps.getRegistryValue(main_key, subkey % (mountpoint, "AutoRun"), "") or\
            regOps.getRegistryValue(main_key, subkey % (mountpoint, "explore"), "") or\
            regOps.getRegistryValue(main_key, subkey % (mountpoint, "open"), "")
            
                                    
    if value:
      suspects.append([smartStr.normalize(mountpoint), smartStr.normalize(value)])
  return suspects or None


def searchAutorun():
  devices = GetLogicalDriveStrings().split("\\\x00")[:-1]
  autoruns = []
  if "A:" in devices:
    devices.remove("A:")
    
  # List comprehention. Isn't it beautiful?
  fixed_devices = [device for device in devices if GetDriveType(device) == DRIVE_FIXED]
  
  for device in fixed_devices:
    try:
      device_content = commandHandler.getOutput(["dir", "/a/b", device + "\\"])
      if "autorun.inf" in device_content or "autorun.exe" in device_content:
        autoruns.append(device)
    except Exception as err:
      continue
  return autoruns
    
