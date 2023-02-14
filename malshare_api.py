#!/usr/bin/env python
# Copyright (C) 2013 - 2016 Malshare Developers.
# Multitool for MalShare API

import os
import re
import json
import argparse
import requests

BASE_HTTP_PATH = "http://malshare.com/"
API_PATHS = {
    "MD5LIST" :"api.php?api_key=%s&action=getlistraw",
    "SOURCES" :"api.php?api_key=%s&action=getsourcesraw",
    
    "DOWNLOAD":"api.php?api_key=%s&action=getfile&hash=%s",
    "DETAILS" :"api.php?api_key=%s&action=details&hash=%s",
    
    "TYPE"    :"api.php?api_key=%s&action=type&type=%s",
}

api_key = "df91336a3be56879597e8bb6e7b98953652889b2c0f17b7eb29012319ba1bd42"

def main():
    largs = parse_args()
    
    if largs['details']:
        uri = API_PATHS['DETAILS'] % (api_key, largs['details'])
        r = api_call(uri)
        if r is not None:
            details = r.json()
            print(json.dumps(details, indent=4, sort_keys=True))
    
    
    elif largs['download']:
        uri = API_PATHS['DOWNLOAD'] % (api_key, largs['download'])
        r = api_call(uri)
        if r is not None:
            try:
                with open(str(largs['download']) + ".malshare", 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                print("[X] Problem saving file")
                print("[E] %s" % e)
    
    elif largs['type']:
        uri = API_PATHS['TYPE'] % (api_key, largs['type'])
        r = api_call(uri)
        if r is not None:
            for rhash in set(r.json()):
                print(rhash)
    
    elif largs['listmd5']:
        uri = API_PATHS['MD5LIST'] % (api_key)
        r = api_call(uri)
        print(r.text.strip())
    
    
    elif largs['listsources']:
        uri = API_PATHS['SOURCES'] % (api_key)
        r = api_call(uri)
        print(r.text.strip())

def api_call(rpath):
    global api_key
    try:
        user_agent = {'User-Agent':'MalShare API Tool v/0.1 beta'}
        r = requests.get(BASE_HTTP_PATH + rpath, headers=user_agent)
        
        if r.status_code == 200:
            if standard_error_check(r.content.decode('utf-8')):
                return r
        else:
            c = r.content.decode('utf-8')
            if standard_error_check(c):
                print(f"[X] API Call Failed: {c}")
                return None
            else:
                return None
    except Exception as e:
        print("[X] API Call Failed: %s" % e)
        return None

def standard_error_check(rtext):
    if (rtext == "Sample not found"):
        print("[X] Sample not Found")
        return False
    
    if (rtext == "ERROR! => Account not activated"):
        print("[X] Bad API Key")
        return False
    
    if (rtext == "Invalid Hash"):
        print("[X] Invalid Hash")
        return False
    
    if ("Sample not found by hash" in rtext):
        print("[X] Hash not found")
        return False
    
    return True

def parse_args():
    global api_key
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--listmd5", help="Pull MD5 List", required=False, action='store_true')
    parser.add_argument("-s", "--listsources", help="Pull MD5 List", required=False, action='store_true')
    
    parser.add_argument("-d", "--download", help="Download File by Hash", required=False)
    parser.add_argument("-l", "--details", help="List File Details", required=False)
    parser.add_argument("-t", "--type", help="Search For Daily files by Type", required=False)
    
    parser.add_argument("-a", "--apikey", help="Set API key for session", required=False)
    
    args = parser.parse_args()
    if stored_api_check() == False:
        if args.apikey:
            api_key = args.apikey
    
    return vars(args)

# Read ~/.malshare and read the first line.  This file only needs the API string in it.
def stored_api_check():
    global api_key
    try:
        if (os.path.exists(os.path.expanduser('~') + '/.malshare')):
            with open(os.path.expanduser('~') + '/.malshare') as handle_api_file:
                api_key = func_parse_api_key(handle_api_file.readlines())
            return True
        elif (os.path.exists('.malshare')):
            with open('.malshare') as handle_api_file:
                api_key = func_parse_api_key(handle_api_file.readlines())
        return True
    except IOError:
        pass
    return False

# Parse the API key and exit if the API key contains any non [A-Za-z0-9]+
def func_parse_api_key(lst_tmp_key):
    str_tmp_key = "".join(lst_tmp_key).rstrip()
    if re.match("^[A-Za-z0-9]+$", str_tmp_key):
        return str_tmp_key

if __name__ == "__main__":
    main()
