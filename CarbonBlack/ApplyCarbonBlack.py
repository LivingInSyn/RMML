'''
This code applies the feed and watchlist definitions 
from a release of RMML onto a carbon black instance
'''
import os
import requests
import sys
import logging
import json
import yaml
import time
import hashlib
from typing import List

HEADERS = {
    'X-Auth-Token': '', # set in __main__
    'Content-Type': 'application/json'
}
RMMDIR = './RMMs'
EXEKEYS = ['Windows', 'MacOS', 'Linux']

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

def build_feed(rmms):
    # build the list of IOCv2s
    iocs = {}
    for rmm in rmms:
        rmm = rmms[rmm]
        for exekey in EXEKEYS:
            if exekey not in rmm['Executables']:
                continue
            if not rmm['Executables'][exekey]:
                continue
            for exe in rmm['Executables'][exekey]:
                if ' ' in exe:
                    exe = f'"{exe}"'
                newioc = build_iocv2_exe(exe)
                iocs[newioc['id']] = newioc
    # build the feed object
    fo = {
        "feedinfo": {
            "name": "RMML-l",
            "provider_url": "https://github.com/livinginsyn/RMML",
            "summary": "Remote Management and Monitoring Tool IOC List",
            "category": "external_threat_intel",
            "source_label": "RMML",
            "alertable": True
        },
        "reports": [{
            "id": "358aa2abf8d0",
            "timestamp": 0,
            "title": "RMML-r",
            "description": "Remote Management and Monitoring Tool IOC List",
            "severity": "7",
            "link": "https://github.com/livinginsyn/RMML",
            "tags": ["RMM"],
            "iocs_v2": ["<IOCv2>"],
            "visibility": "visible"
        }]
    }
    fo['reports'][0]['timestamp'] = int(time.time())
    fo['reports'][0]['iocs_v2'] = list(iocs.values())

    return fo

def build_watchlist():
    wo = {
        "name": "RMML",
        "description": "Remote Management and Monitoring Tool IOC List",
        "tags_enabled": True,
        "alerts_enabled": True,
        "alert_classification_enabled": False,
        "classifier": {
            "key": "feed_id",
            "value": "ABCDEFGHIJKLMNOPQRSTU"
        }
    }
    return wo

def build_release(exclusions: List[str]):
    # build the RMMs dict
    rmms = {}
    for filename in os.listdir(RMMDIR):
        file = os.path.join(RMMDIR, filename)
        if os.path.isfile(file):
            with open(file, 'r') as f:
                rmm = yaml.safe_load(f)
            rmm_name = file.removeprefix(RMMDIR).removesuffix('.yml').removesuffix('.yaml')[1:]
            if rmm_name in exclusions:
                logging.warning(f"skipping {rmm_name} because it's excluded")
                continue
            rmms[rmm_name] = rmm
    # for each RMM, generate the stuff
    feed = build_feed()
    watchlist = build_watchlist()
    return feed, watchlist

def check_feed_exists(urlbase, org_key):
    url = f'{urlbase}/threathunter/feedmgr/v2/orgs/{org_key}/feeds?include_public=false'
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't get feeds from CB. Error code: {r.status_code}")
    feeds = r.json()
    # find the feedid if we can
    feed_id = None
    for feed in feeds['results']:
        if feed['name'] == 'RMML-l':
            feed_id = feed['id']
            break
    # if not, return None so we can create it
    if not feed_id:
        return None, None
    # if yes, get the report ID from it
    url = f'{url_base}/threathunter/feedmgr/v2/orgs/{org_key}/feeds/{feed_id}/reports'
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't get feeds details from CB. Error code: {r.status_code}")
    report_id = r.json()['results'][0]['id']
    return feed_id, report_id

def create_feed(url_base, org_key, feed):
    # returns feed_id, report_id
    url = f'{url_base}/threathunter/feedmgr/v2/orgs/{org_key}/feeds'
    r = requests.post(url, json.dumps(feed), headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't create the feed. Error code: {r.status_code}")
    return r.json()['id'], feed['reports'][0]['id']

def update_report(urlbase, org_key, feed_id, report_id, feed):
    url = f'{urlbase}/threathunter/feedmgr/v2/orgs/{org_key}/feeds/{feed_id}/reports/{report_id}'
    r = requests.put(url, headers=HEADERS, data=json.dumps(feed['reports'][0]))
    if r.status_code == 400 and 'timestamp is out-of-date' in r.content.decode():
        print("no update, exiting")
        sys.exit(0)
    if r.status_code != 200:
        print(r.content)
        logging.fatal(f"Couldn't update the report. Error code: {r.status_code}")

def watchlist_exists(urlbase, org_key):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists'
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't get watchlists. Error code: {r.status_code}")
    for wl in r.json()['results']:
        if wl['name'] == f'RMML':
            return wl['id']
    return None

def create_watchlist(urlbase, org_key, watchlist, feed_id):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists'
    watchlist['classifier']['value'] = feed_id
    r = requests.post(url, headers=HEADERS, data=json.dumps(watchlist))
    if r.status_code != 200:
        logging.fatal(f"Couldn't create the Watchlist. Error code: {r.status_code}")
    logging.info('created the watchlist')

def update_watchlist(urlbase, org_key, wl_id, watchlist, feed_id):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists/{wl_id}'
    watchlist['classifier']['value'] = feed_id
    r = requests.put(url, headers=HEADERS, data=json.dumps(watchlist))
    if r.status_code != 200:
        logging.fatal(f"Couldn't update the Watchlist. Error code: {r.status_code}")
    logging.info('updated the watchlist')

if __name__ == "__main__":
    # API Secret and API ID are stored in env vars
    api_secret = os.getenv("CB_SECRET")
    api_id = os.getenv("CB_APIID")
    url_base = os.getenv('CB_URL', 'https://defense-prod05.conferdeploy.net')
    if not api_secret:
        raise ValueError("CB_SECRET not set")
    if not api_id:
        raise ValueError("CB_APIID not set")
    HEADERS['X-Auth-Token'] = f'{api_secret}/{api_id}'
    # python3 ApplyCarbonBlack.py <comma separated list of exclusions> 
    if len(sys.argv) < 2:
        logging.warning('No RMM set, proceding with no exclusions')
        exclusions = []
    else:
        exclusions = sys.argv[1]
        exclusions = exclusions.split(',')
    feed, watchlist = build_release(exclusions)
    # check if the feed exists and create it if it doesn't. Update the report
    # if it does
    feed_id, report_id = check_feed_exists(url_base, api_id)
    created_feed = False
    if not report_id:
        feed_id, report_id = create_feed(url_base, api_id, feed)
        created_feed = True
    else:
        update_report(url_base, api_id, feed_id, report_id, feed)
    # create or update the watchlist
    watchlist_id = watchlist_exists(url_base, api_id)
    if not watchlist_id:
        create_watchlist(url_base, api_id, watchlist, feed_id)
    else:
        update_watchlist(url_base, api_id, watchlist_id, watchlist, feed_id)
    logging.info('finished!')
