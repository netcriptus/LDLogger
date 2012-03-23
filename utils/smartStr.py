#!/usr/bin/env python
# encoding: utf-8
"""
smartStr.py

Created by Fernando Cezar on 2012-03-23.
Copyright (c) 2012 __MyCompanyName__. All rights reserved.
"""
import types
import errorHandler

def normalize(string):
  possible_encodings = ["utf-8", "utf-16", "iso8859-1", "windows-1250",
                        "windows-1252", "windows-1251", "iso-8859-15"]
                        
  for encoding in possible_encodings:
    try:
      encoded_string = __smart_str(string, from_encoding = encoding)
      return encoded_string
    except:
      continue
      
  errorHandler.logMessage("normalization", "Could not decode %s" % repr(string))
  return "%s (Error decoding)" % repr(string)
  


def __smart_str(s, encoding='utf-8', errors='strict', from_encoding='iso8859-1'):
  if type(s) in (int, long, float, types.NoneType):
    return str(s)
  elif type(s) is str:
      return s.decode(from_encoding, errors).encode(encoding, errors)
  elif type(s) is unicode:
    return s.encode(encoding, errors)
  elif hasattr(s, '__str__'):
    return __smart_str(str(s), encoding, errors, from_encoding)
  elif hasattr(s, '__unicode__'):
    return __smart_str(unicode(s), encoding, errors, from_encoding)
  else:
    return __smart_str(str(s), encoding, errors, from_encoding)

