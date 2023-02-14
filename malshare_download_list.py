#! /usr/bin/env python
# Download files with given hashes.json file

import argparse
import json
import logging
import os
import sys
from multiprocessing.pool import Pool
import requests
import tqdm
import re

api_key = "d5cb268eddfce4bce2eaf2ed2aee868032ce7d6dd6a645e7f175c76b94b29a"
api_key = "f25121c2270089cad3c12769e1b404b679252b0ed0fe0e48686c079f322a54de"
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.WARNING)

def download_file_by_hash(file_hash):
    logging.debug("Downloading {}".format(file_hash))
    try:
        malshare_url = "http://malshare.com/api.php"
        payload = {'action':'getfile', 'api_key':api_key, 'hash':file_hash}
        user_agent = {'User-agent':'wget_malshare daily 1.0'}
        
        r = requests.get(malshare_url, params=payload, headers=user_agent)
        sample = r.content
        
        if sample == "Sample not found":
            logging.error("Sample not Found")
            return None
        if sample == "ERROR! => Account not activated":
            logging.error("Bad API Key")
            return None
        if sample == "Invalid Hash..." or len(sample) == 15:
            logging.error(f"\r\ninvalid hash {file_hash} ({sample})")
            return None
        if "you need this increased" in sample.decode('utf-8', errors='ignore'):
            logging.error(f"\r\nwe're hit the limit")
            sys.exit(0)
        
        with open(os.path.join("files", file_hash), mode="wb") as fh:
            fh.write(sample)
            logging.info("{} saved to files".format(file_hash))
            print(f'\r\n{file_hash}: {len(sample)} bytes')
    
    except Exception as e:
        logging.error("download_file_by_hash: Problem connecting. Please Try again.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)

def download_list(api_k, hash_list):
    global api_key, pool
    if api_k:
        api_key = api_k
    files = json.load(open(hash_list))
    pool = Pool(os.cpu_count())
    for _ in tqdm.tqdm(pool.imap_unordered(download_file_by_hash, files), total=len(files)):
        pass

if __name__ == "__main__":
    from pprint import pprint
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--apikey", help="API Key", required=False)
    parser.add_argument("-f", "--hash_list", help="File containing list of hashes in json format", required=True)
    args = parser.parse_args()
    
    hashes = requests.get("https://malshare.com/sitemap.php")
    content = hashes.content.decode('utf-8')
    mm = re.findall("(.[a-fA-F0-9]{64})", content)
    
    try:
        os.mkdir('files')
    except:
        pass
    
    hashes = set([h[1:] for h in mm if h[0] != "=" and not os.path.exists(f'files/{h[1:]}')])
    open("hashes.json", "wt").write(json.dumps(list(hashes), indent=4))
    download_list(api_key, args.hash_list)
