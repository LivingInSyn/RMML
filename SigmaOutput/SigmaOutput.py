import yaml
import json
import os

RMMDIR = './RMMs'
OUTDIR = './ci-output/sigma'

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
        # "attack.command-and-control", 
        # "attack.t1219"
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



sigmas = []
for filename in os.listdir(RMMDIR):
    file = os.path.join(RMMDIR, filename)
    if os.path.isfile(file):
        with open(file, 'r') as f:
            rmm = yaml.safe_load(f)
            rmm_sigma = sigma_template.copy()
            rmm_name = file.removeprefix(RMMDIR).removesuffix('.yml').removesuffix('.yaml')[1:]
            rmm_sigma['title'] = f'RMML-{rmm_name}'
            
