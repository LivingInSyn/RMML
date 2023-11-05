import yaml
import sys
import os
import hashlib
import time
import json
import shutil

EXEKEYS = ['Windows', 'MacOS', 'Linux']
CIPATH = './ci-output'
CBCIPATH = './ci-output/cbout'
OUTPUT_NAME = './ci-output/carbon_black'

def build_iocv2_exe(process):
    iocv2 = {
        "id": "465ea2da5354",
        "match_type": "query",
        "values": ["process_name:some_rmm.exe"],
        "link": "https://github.com/livinginsyn/RMML"
    }
    query = f'process_name:{process}'
    m = hashlib.sha1()
    m.update(query.encode())
    iocv2['id'] = m.hexdigest()[:12]
    iocv2['values'][0] = query
    return iocv2

def build_feed(rmms, exclusion):
    # build the list of IOCv2s
    iocs = []
    for rmm in rmms:
        if rmm == exclusion:
            continue
        rmm = rmms[rmm]
        for exekey in EXEKEYS:
            if exekey not in rmm['Executables']:
                continue
            if not rmm['Executables'][exekey]:
                continue
            for exe in rmm['Executables'][exekey]:
                if ' ' in exe:
                    exe = f'"{exe}"'
                iocs.append(build_iocv2_exe(exe))
    # build the feed object
    fo = {
        "feedinfo": {
            "name": "RMML-l - <exclusion>",
            "provider_url": "https://github.com/livinginsyn/RMML",
            "summary": "Remote Management and Monitoring Tool IOC List",
            "category": "external_threat_intel",
            "source_label": "RMML",
            "alertable": True
        },
        "reports": [{
            "id": "358aa2abf8d0",
            "timestamp": 0,
            "title": "RMML-r - <exclusion>",
            "description": "Remote Management and Monitoring Tool IOC List",
            "severity": "7",
            "link": "https://github.com/livinginsyn/RMML",
            "tags": ["RMM"],
            "iocs_v2": ["<IOCv2>"],
            "visibility": "visible"
        }]
    }
    fo['feedinfo']['name'] = f'RMML-l - {exclusion}'
    fo['reports'][0]['timestamp'] = int(time.time())
    fo['reports'][0]['title'] = f'RMML-r - {exclusion}'
    fo['reports'][0]['iocs_v2'] = iocs

    return fo

def build_watchlist(exclusion):
    wo = {
        "name": "RMML - <exclusion>",
        "description": "Remote Management and Monitoring Tool IOC List",
        "tags_enabled": False,
        "alerts_enabled": True,
        "alert_classification_enabled": False,
        "report_ids": ["358aa2abf8d0"]
    }
    wo['name'] = f'RMML - {exclusion}'
    return wo

if __name__ == '__main__':
    with open("./rmm.yml", "r") as f:
        try:
            y = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f'Error loading yaml: {exc}')
            sys.exit(1)
    rmms = y['RMMs']
    # make sure output folder exists and create it if it doesn't
    if not os.path.exists(CIPATH):
        os.makedirs(CIPATH)
    if not os.path.exists(CBCIPATH):
        os.makedirs(CBCIPATH)
    # generate the output files for the feeds
    for rmm in rmms:
        # the RMM here is the one we're excluding from alerting
        feed = build_feed(rmms, rmm)
        watchlist = build_watchlist(rmm)
        with open(f'{CBCIPATH}/feed-{rmm}.json', 'w') as f:
            f.write(json.dumps(feed, indent=2))
        with open(f'{CBCIPATH}/watchlist-{rmm}.json', 'w') as f:
            f.write(json.dumps(watchlist, indent=2))
    # run one more time with the 'rmm' of ALL, so we can support no exlusions
    rmm = 'ALL'
    feed = build_feed(rmms, rmm)
    watchlist = build_watchlist(rmm)
    with open(f'{CBCIPATH}/feed-{rmm}.json', 'w') as f:
        f.write(json.dumps(feed, indent=2))
    with open(f'{CBCIPATH}/watchlist-{rmm}.json', 'w') as f:
        f.write(json.dumps(watchlist, indent=2))
    # create a zip file of the outputs
    shutil.make_archive(OUTPUT_NAME, 'zip', CBCIPATH)
