'''
This code applies the feed and watchlist definitions 
from a release of RMML onto a carbon black instance
'''
import os
import requests
import tempfile
import secrets
import shutil
import sys
import logging
import json

HEADERS = {
    'X-Auth-Token': '', # set in __main__
    'Content-Type': 'application/json'
}

def get_latest_release():
    tempdir = tempfile.gettempdir()
    url = 'https://github.com/livinginsyn/RMML/releases/latest/download/carbon_black.zip'
    r = requests.get(url, allow_redirects=True)
    if r.status_code != 200:
        raise Exception('Error downloading RMML CI Build')
    dlfile = os.path.join(tempdir, 'carbon_black.zip')
    with open(dlfile, 'wb') as f:
        f.write(r.content)
    outdir = f'carbon_black_{secrets.token_hex(4)}'
    outdir = os.path.join(tempdir, outdir)
    os.makedirs(outdir)
    shutil.unpack_archive(dlfile, outdir, 'zip')
    return outdir

def check_feed_exists(urlbase, org_key, rmm):
    url = f'{urlbase}/threathunter/feedmgr/v2/orgs/{org_key}/feeds?include_public=false'
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't get feeds from CB. Error code: {r.status_code}")
    feeds = r.json()
    # find the feedid if we can
    feed_id = None
    for feed in feeds['results']:
        if feed['name'] == f'RMML-l - {rmm}':
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

def create_feed(url_base, org_key, feed_json_path):
    # returns feed_id, report_id
    url = f'{url_base}/threathunter/feedmgr/v2/orgs/{org_key}/feeds'
    with open(feed_json_path, 'r') as f:
        feed_json = f.read()
    feed_json_parsed = json.loads(feed_json)
    r = requests.post(url, feed_json, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't create the feed. Error code: {r.status_code}")
    return r.json()['id'], feed_json_parsed['reports'][0]['id']

def update_report(urlbase, org_key, feed_id, report_id, feed_json_path):
    url = f'{urlbase}/threathunter/feedmgr/v2/orgs/{org_key}/feeds/{feed_id}/reports/{report_id}'
    with open(feed_json_path, 'r') as f:
        feed_json = f.read()
    feed_json_parsed = json.loads(feed_json)
    r = requests.put(url, headers=HEADERS, data=json.dumps(feed_json_parsed['reports'][0]))
    if r.status_code == 400 and 'timestamp is out-of-date' in r.content.decode():
        print("no update, exiting")
        sys.exit(0)
    if r.status_code != 200:
        logging.fatal(f"Couldn't update the report. Error code: {r.status_code}")

def watchlist_exists(urlbase, org_key, rmm):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists'
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logging.fatal(f"Couldn't get watchlists. Error code: {r.status_code}")
    for wl in r.json()['results']:
        if wl['name'] == f'RMML - {rmm}':
            return wl['id']
    return None

def create_watchlist(urlbase, org_key, wl_json_path, feed_id):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists'
    with open(wl_json_path, 'r') as f:
        wl_json = f.read()
    wl_json_parsed = json.loads(wl_json)
    wl_json_parsed['classifier']['value'] = feed_id
    r = requests.post(url, headers=HEADERS, data=json.dumps(wl_json_parsed))
    if r.status_code != 200:
        logging.fatal(f"Couldn't create the Watchlist. Error code: {r.status_code}")
    logging.info('created the watchlist')

def update_watchlist(urlbase, org_key, wl_id, wl_json_path, feed_id):
    url = f'{urlbase}/threathunter/watchlistmgr/v3/orgs/{org_key}/watchlists/{wl_id}'
    with open(wl_json_path, 'r') as f:
        wl_json = f.read()
    wl_json_parsed = json.loads(wl_json)
    wl_json_parsed['classifier']['value'] = feed_id
    r = requests.put(url, headers=HEADERS, data=json.dumps(wl_json_parsed))
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
    # python3 ApplyCarbonBlack.py <RMM> 
    if len(sys.argv) < 2:
        logging.warning('No RMM set, proceding with: ALL')
        exclusion = 'ALL'
    else:
        exclusion = sys.argv[1]
    if not os.getenv("RMML_DEBUG"):
        cbfiles = get_latest_release()
    else:
        cbfiles = "./ci-output/cbout"
    feedpath = os.path.join(cbfiles, f'feed-{exclusion}.json')
    if not os.path.exists(feedpath):
        logging.fatal(f"Couldn't find {feedpath}, did you input the wrong RMM?")
    wlpath = os.path.join(cbfiles, f'watchlist-{exclusion}.json')
    if not os.path.exists(wlpath):
        logging.fatal(f"Couldn't find {wlpath}, did you input the wrong RMM?")
    # check if the feed exists and create it if it doesn't. Update the report
    # if it does
    feed_id, report_id = check_feed_exists(url_base, api_id, exclusion)
    created_feed = False
    if not report_id:
        feed_id, report_id = create_feed(url_base, api_id, feedpath)
        created_feed = True
    else:
        update_report(url_base, api_id, feed_id, report_id, feedpath)
    # create or update the watchlist
    watchlist_id = watchlist_exists(url_base, api_id, exclusion)
    if not watchlist_id:
        create_watchlist(url_base, api_id, wlpath, feed_id)
    else:
        update_watchlist(url_base, api_id, watchlist_id, wlpath, feed_id)
    logging.info('finished!')
