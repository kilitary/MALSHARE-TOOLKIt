#!/usr/bin/env python
# Copyright (C) 2013 - 2018 Malshare Developers.
# Written by Silas Cutler
# Quick search tool for  MalShare API

import sys
import json
import requests

api_key = ""
if api_key != "":
	url="https://malshare.com/api.php?api_key=%s&action=search&query=%s" % (api_key, sys.argv[1] )
	r = requests.get(url)
	print(json.dumps(r.json(), sort_keys=True, indent=4, separators=(',', ': ')))
else:
	print("Please set API key")
