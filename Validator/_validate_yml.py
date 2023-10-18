import yaml
import sys

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

with open("./rmm.yml", "r") as f:
    try:
        y = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print(f'Error loading yaml: {exc}')
        sys.exit(1)
    if 'RMMs' not in y:
        print('RMMs not in yaml')
        sys.exit(1)
    for r in y['RMMs']:
        rmm = y['RMMs'][r]
        if 'Executables' not in rmm:
            print(f'Executables not defined in {r}')
            sys.exit(1)
        if 'NetConn' not in rmm:
            print(f'NetConn not defined in {r}')
            sys.exit(1)
        check_executables(r, rmm['Executables'])
        check_netconn(r, rmm['NetConn'])
    if len(ERRORS) == 0:
        sys.exit(0)
    else:
        for e in ERRORS:
            print(e)
        sys.exit(1)
