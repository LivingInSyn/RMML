import yaml
import sys

EXEKEYS = ['Windows', 'MacOS', 'Linux']

# MVP is something like:
# process_name:AteraAgent.exe OR process_name:AgentPackageNetworkDiscoveryWG.exe OR ...
with open("./rmm.yml", "r") as f:
    try:
        y = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print(f'Error loading yaml: {exc}')
        sys.exit(1)
    query = ''
    for rmm in y['RMMs']:
        rmm = y['RMMs'][rmm]
        for exekey in EXEKEYS:
            if exekey not in rmm['Executables']:
                continue
            if not rmm['Executables'][exekey]:
                continue
            for exe in rmm['Executables'][exekey]:
                if ' ' in exe:
                    exe = f'"{exe}"'
                query = f'{query} process_name:{exe} OR'
    # remove the trailing or and the leading space
    query = query[:-3]
    query = query[1:]
print(query)