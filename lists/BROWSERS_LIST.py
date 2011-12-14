#!/usr/bin/env python
# encoding: utf-8

BROWSERS = {"IE": {"key": "HKEY_LOCAL_MACHINE",
                   "subkey": "SOFTWARE\\Microsoft\\Internet Explorer",
                   "name": "Internet Explorer"},
            "FIREFOX": {"key": "HKEY_LOCAL_MACHINE",
                        "subkey": "SOFTWARE\\Mozilla\\Mozilla Firefox",
                        "name": "Mozilla Firefox"},
            "CHROME": {"key": "HKEY_CURRENT_USER",
                       "subkey": "Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome",
                       "name": "Google Chrome"}}
