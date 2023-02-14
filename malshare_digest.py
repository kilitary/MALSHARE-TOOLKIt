#! /usr/bin/env python
# Copyright (C) 2013 Malshare Developers.
# Written by Blevene github.com/Blevene

# Open and catalog list of samples observed for a given date
# on Malshare.com, location: http://www.malshare.com/daily/malshare.current.txt
# To Do:
# [x] Create output file (csv or txt?)
# [x] Store each md5 as a csv with 'hash' : 'date' mapping

import requests
import argparse
import csv
from sys import argv
from datetime import datetime, date

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--outfile", help="Pull the most recent Malshare digest", required=True)
    args = parser.parse_args()
    
    mal_digest = requests.get(url='http://www.malshare.com/daily/malshare.current.txt').content.decode('utf-8')
    mal_digest = list(mal_digest)
    pull_time = [str(date.today())] * len(mal_digest)
    strip_list = [x.strip('\n') for x in mal_digest]
    dictionary = dict(zip(strip_list, pull_time))
    outfile_name = args.outfile + '.csv'
    writer = csv.writer(open( outfile_name , 'a'))
    for key, value in dictionary.items():
        if (key):
            writer.writerow([key, value])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(" [X] Shutting Down")
