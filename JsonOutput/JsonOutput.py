import yaml
import json
import os

RMMDIR = './RMMs'
OUTDIR = './ci-output'
OUTFILE = f'{OUTDIR}/rmms.json'

rmms = {}
for filename in os.listdir(RMMDIR):
    file = os.path.join(RMMDIR, filename)
    if os.path.isfile(file):
        with open(file, 'r') as f:
            rmm = yaml.safe_load(f)
            rmm_name = file.removeprefix(RMMDIR).removesuffix('.yml').removesuffix('.yaml')[1:]
            rmms[rmm_name] = rmm

if not os.path.exists(OUTDIR):
    os.mkdir(OUTDIR)
with open(OUTFILE, 'w') as f:
    f.write(json.dumps(rmms, indent=2))

