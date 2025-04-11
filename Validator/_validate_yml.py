import yaml
import sys
import os
import datetime
import json

RMMDIR = './RMMs'
OSES = ['Windows','MacOS','Linux']
ERRORS = []

def check_executables(r, exe):
    # check keys
    keys = ['SignerSubjectName', 'MacOSSigner', 'Windows', 'MacOS', 'Linux']
    for k in keys:
        if k not in exe:
            ERRORS.append(f'Missing key {k} in executables on {r}')
    if len(ERRORS) > 1:
        return
    # check types of signer data
    if not isinstance(exe['SignerSubjectName'], (str,type(None))):
        ERRORS.append(f'Bad data type on SignerSubjectName on {r}')
    if not isinstance(exe['MacOSSigner'], (str,type(None))):
        ERRORS.append(f'Bad data type on MacOSSigner on {r}')
    if len(ERRORS) > 1:
        return
    # check the arrays
    for os in OSES:
        if not isinstance(exe[os], (list, type(None))):
            ERRORS.append(f'Bad data type on {os} Executables on {r}')
    if len(ERRORS) > 0:
        return
    # check the contents of  the arrays
    for os in OSES:
        if isinstance(exe[os], (list)):
            for e in exe[os]:
                if not isinstance(e, (str)):
                    ERRORS.append(f'Found a non-string in {os} exes. Value: {e}')

def check_netconn(r, nc):
    keys = ['Domains', 'Ports']
    for k in keys:
        if k not in nc:
            ERRORS.append(f'Missing key {k} in netconn on {r}')
    if len(ERRORS) > 0:
        return
    # check types
    for k in keys:
        if not isinstance(nc[k], (list,type(None))):
            ERRORS.append(f'Bad data type on {k} on {r}')
    if len(ERRORS) > 1:
        return
    # check values in domains
    if nc['Domains']:
        for d in nc['Domains']:
            if not isinstance(d, (str)):
                ERRORS.append(f'Found a non-string in {r} Domains. Value: {d}')
    if nc['Ports']:
        for p in nc['Ports']:
            if not isinstance(p, (int)):
                ERRORS.append(f'Found a non-int in {r} Ports. Value: {p}')

def check_meta(r, meta):
    keys = ['ID', 'Description', 'Date', 'Modified', 'References']
    for k in keys:
        if k not in meta:
            ERRORS.append(f'Missing key {k} in Meta on {r}')
    if len(ERRORS) > 0:
        return
    if not isinstance(meta['Description'], str):
        ERRORS.append(f"Description on {r} isn't a string")
    if not isinstance(meta['Date'], datetime.date):
        ERRORS.append(f"Date on {r} isn't a date")
    if not isinstance(meta['Modified'], datetime.date):
        ERRORS.append(f"Modified on {r} isn't a date")
    if not isinstance(meta['References'], list):
        ERRORS.append(f"References on {r} isn't a list")

def check_serialize(r, rmm_test):
    try:
        _jout = json.dumps(rmm_test, indent=2, default=str)
    except Exception as ex: # pylint: disable=broad-except
        ERRORS.append(f'Couldnt JSON serialize RMM: {r}! Exception: {ex}')


IDs = set()
for filename in os.listdir(RMMDIR):
    file = os.path.join(RMMDIR, filename)
    # checking if it is a file
    if os.path.isfile(file):
        # load the file
        with open(file, 'r') as f:
            rmm = yaml.safe_load(f)
        rmm_name = file.removeprefix(RMMDIR).removesuffix('.yml').removesuffix('.yaml')[1:]
        if rmm_name == 'Tailscale':
            a = 'foo'
        if 'Executables' not in rmm:
            print(f'Executables not defined in {rmm_name}')
            sys.exit(1)
        if 'NetConn' not in rmm:
            print(f'NetConn not defined in {rmm_name}')
            sys.exit(1)
        if 'Meta' not in rmm:
            print(f'Meta not defined in {rmm_name}')
            sys.exit(1)
            # check the IDs
        if 'ID' not in rmm['Meta']:
            print(f'ID not defined in {rmm_name}, meta section')
            sys.exit(1)
        if rmm['Meta']['ID'] not in IDs:
            IDs.add(rmm['Meta']['ID'])
        else:
            print(f'DUPLICATE ID defined in {rmm_name}, meta section')
            sys.exit(1)
        check_executables(rmm_name, rmm['Executables'])
        check_netconn(rmm_name, rmm['NetConn'])
        check_meta(rmm_name, rmm['Meta'])
        check_serialize(rmm_name, rmm)
if len(ERRORS) == 0:
    sys.exit(0)
else:
    for e in ERRORS:
        print(e)
    sys.exit(1)
