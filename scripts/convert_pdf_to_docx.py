#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Converter Disabled:
To protect server resources and prevent hosting freezing (RLIMIT_NPROC / 40 processes),
conversion is handled exclusively via the official iLovePDF Cloud API.
"""
import sys
import json

print("__RESULT_JSON__:" + json.dumps({
    "success": False,
    "error": "Python local vector engine has been permanently disabled to prevent hosting server overload. Please use iLovePDF Cloud API."
}, ensure_ascii=False))
sys.exit(1)
