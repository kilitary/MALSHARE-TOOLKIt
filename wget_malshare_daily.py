#! /usr/bin/env python
# Copyright (C) 2013 Malshare Developers.
# Pull All Daily MD5 Hashes

# 02/21/2014 Modified by Jun Xie <jxie2004@gmail.com>
#     to download a single day: wget_malshare_daily -d 2014-01-27
#     to download samples within a range: wget_malshare_daily -s 2014-01-27 -e 2014-02-07
#
# Sciprt will create the folder named by date automatically under current directory

import argparse
import logging
import requests
import sys
import os
import re
import sys
import string
from datetime import datetime, date, timedelta

api_key = ""

logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.WARNING)

def main():
    global api_key
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--apikey", help="API Key", required=False)
    parser.add_argument("-o", "--outfolder", help="Folder to save samples to", required=False)
    parser.add_argument("-x", "--vxcage", help="VXCage server", required=False)
    parser.add_argument("-d", "--date", type=str,
                        help="Specify the date to download. If not specified, download today's. Format:yyyy-mm-dd.",
                        required=False)
    parser.add_argument("-s", "--sdate", type=str, help="Specify the start date to download. Format:yyyy-mm-dd.",
                        required=False)
    parser.add_argument("-e", "--edate", type=str, help="Specify the end date to download. Format:yyyy-mm-dd.",
                        required=False)
    global api_key
    
    args = parser.parse_args()
    if args.apikey:
        api_key = args.apikey
    
    if (not api_key):
        logging.error("API Key not entered")
        sys.exit(1)
    
    if args.sdate and args.edate:
        start_date = datetime.strptime(args.sdate, '%Y-%m-%d').date()
        end_date = datetime.strptime(args.edate, '%Y-%m-%d').date()
        if end_date < start_date:
            print("end_date(%s) is earlier than start_date(%s)" % (str(end_date), str(start_date)))
            sys.exit(1)
        temp_date = start_date
        if not args.outfolder:
            args.outfolder = "./"
        while temp_date <= end_date:
            temp_date_str = str(temp_date)
            temp_date += timedelta(days=1)
            print("%s" % temp_date_str)
            sub_path = temp_date_str + '/malshare_fileList.' + temp_date_str + '.txt'
            # if not args.outfolder:
            outfolder = args.outfolder + temp_date_str
            if (os.path.exists(outfolder)):
                # if the directory exist, bypass it, cause we already downloaded this folder
                continue
            download_daily(args.vxcage, outfolder, sub_path)
        sys.exit(0)
    
    if args.date:
        date_str = str(datetime.strptime(args.date, '%Y-%m-%d').date())
        sub_path = date_str + '/malshare_fileList.' + date_str + '.txt'
        
        # automatically create date directory under current directory if outfolder is not specified
        if not args.outfolder:
            args.outfolder = date_str
    else:
        sub_path = 'malshare.current.txt'
    print("sub_path", sub_path)
    # sys.exit(0)
    
    # download samples of this date
    download_daily(args.vxcage, args.outfolder, sub_path)

def download_daily(vxcage, outfolder, sub_path):
    if outfolder:
        if (not os.path.exists(outfolder)):
            os.makedirs(outfolder)
        # os.chdir(args.outfolder)
    
    for md5_hash in pull_daily_list(sub_path):
        if "not found" in md5_hash:
            print("%s doesn't exist! skip." % sub_path)
            os.rmdir(outfolder)
            break
        if (md5_hash):
            logging.info("Downloading %s" % md5_hash)
            print(md5_hash)
            pull_file(md5_hash, vxcage, outfolder)

def pull_daily_list(sub_path):
    try:
        url = "http://www.malshare.com/daily/" + sub_path
        print(url)
        user_agent = {'User-agent':'wget_malshare daily 1.0'}
        
        r = requests.get(url, headers=user_agent)
        for line in r.content.decode('utf-8').split('\n'):
            logging.info("Yield line: %s" % line)
            yield line
        logging.debug("No more lines")
    
    except Exception as e:
        logging.error("Problem connecting.  Please Try again.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        logging.error("Return None")
        yield None
        pass  # in batch download mode, if one date doesn't exist, skip to next date

def pull_file(file_hash, vxcage, outfolder):
    try:
        if not outfolder:
            outfolder = 'samples'
        
        malshare_url = "http://malshare.com/sampleshare.php"
        payload = {'action':'getfile', 'api_key':api_key, 'hash':file_hash}
        user_agent = {'User-agent':'wget_malshare daily 1.0'}
        
        r = requests.get(malshare_url, params=payload, headers=user_agent)
        
        sample = r.content.decode('utf-8')
        
        if (sample == "Sample not found" or "not found" in sample):
            logging.error("Sample not Found")
            return None
        if (sample == "ERROR! => Account not activated"):
            logging.error("Bad API Key")
            return None
        
        if outfolder:
            open(os.path.join(outfolder, file_hash), "wb").write(sample)
            logging.info("Saved %s" % file_hash)
        
        if vxcage:
            vxcage_url = vxcage + "/malware/add"
            files = {'file':sample}
            payload = {'tags':'malshare'}
            r = requests.post(vxcage_url, files=files, data=payload, headers=user_agent)
            if r.json()['message'] == 'added':
                logging.info("Uploaded %s to VXCage" % file_hash)
    except Exception as e:
        logging.error("pull_file: Problem connecting. Please Try again.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)

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

def func_parse_api_key(lst_tmp_key):
    str_tmp_key = "".join(lst_tmp_key).rstrip()
    if re.match("^[A-Za-z0-9]+$", str_tmp_key):
        return str_tmp_key

if __name__ == "__main__":
    main()
