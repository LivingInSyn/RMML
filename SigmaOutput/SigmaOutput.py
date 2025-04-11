import yaml
import json
import os
import logging
import copy

RMMDIR = './RMMs'
OUTDIR = './ci-output/sigma'
# ensure we don't get references in output yaml
yaml.Dumper.ignore_aliases = lambda *args : True


sigma_template = {
    "title": "",
    "id": "", # guid
    "status": "experimental",
    "related": [
        # {
        #     "id": "065b00ca-5d5c-4557-ac95-64a6d0b64d86", 
        #     "type": "similar"
        # }
    ],
    "description": "",
    "references": [
        ""
    ],
    "author": "RMML Authors",
    "date": '', # YYYY-MM-DD
    "modified": '', # YYYY-MM-DD
    "tags": [
        "attack.command-and-control", 
        "attack.t1219"
    ],
    "logsource": {
        "category": "process_creation",
        "product": "windows"
    },
    "detection": None,
    # {
    #     "selection": [
    #         {"Image|endswith": "\\AnyDesk.exe"},
    #         {"Description": "AnyDesk"},
    #         {"Product": "AnyDesk"},
    #         {"Company": "AnyDesk Software GmbH"},
    #     ],
    #     "condition": "selection",
    # },
    "falsepositives": ["Legitimate use"],
    "level": "medium",
}

def generate_sigma(eos, filename):
    try:
        file = os.path.join(RMMDIR, filename)
        if os.path.isfile(file):
            with open(file, 'r') as f:
                rmm = yaml.safe_load(f)
                if eos not in rmm['Executables'] or not rmm['Executables'][eos]:
                    logging.info('RMM %s doesn\'t have OS: %s', filename, eos)
                    return
                rmm_sigma = copy.deepcopy(sigma_template)
                rmm_name = file.removeprefix(RMMDIR).removesuffix('.yml').removesuffix('.yaml')[1:]
                rmm_sigma['title'] = f'RMML-{rmm_name}-{eos}'
                rmm_sigma['id'] = f"{rmm['Meta']['ID']}-{eos.lower()}"
                # add to a list of IDs so that we can add it to all of them when
                # we're done building the base ('related')
                ids.append(rmm_sigma['id'])
                rmm_sigma['description'] = rmm['Meta']['Description']
                rmm_sigma['references'] = rmm['Meta']['References']
                rmm_sigma['date'] = rmm['Meta']['Date']
                rmm_sigma['modified'] = rmm['Meta']['Modified']
                # no change to tags, maybe later
                rmm_sigma['logsource']['product'] = eos.lower()
                # detection is next
                no_wildcards = []
                has_wildcards = []
                for exe in rmm['Executables'][eos]:
                    if '*' not in exe:
                        no_wildcards.append(exe)
                    else:
                        has_wildcards.append(exe)
                rmm_sigma['detection'] = {}
                rmm_sigma['detection']['selection1'] = {"Image|endswith": no_wildcards}
                if len(has_wildcards) == 0:
                    rmm_sigma['detection']['condition'] = 'selection1'
                else:
                    rmm_sigma['detection']['selection2'] = {"Image": has_wildcards}
                    rmm_sigma['detection']['condition'] = 'selection1 or selection2'
                # no change to falsepositives
                # no change to level
                
                # add to the output
                return rmm_sigma
                
    except Exception as e:
        logging.warning("Error transforming %s. Error: %s", filename, e)
        return None


sigmas = []
ids = []
for filename in os.listdir(RMMDIR):
    for eos in ['Windows', 'MacOS', 'Linux']:
        rmm_sigma = generate_sigma(eos, filename)
        if rmm_sigma:
            sigmas.append(rmm_sigma)

if not os.path.exists(OUTDIR):
    os.mkdir(OUTDIR)
for s in sigmas:
    outfile = os.path.join(OUTDIR, s['title'])
    outfile = outfile + '.yml'
    with open(outfile, 'w') as f:
        f.write(yaml.dump(s))