import yaml
import sys

if __name__ == '__main__':
    with open("./_rmm.yml", "r") as f:
        try:
            y = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f'Error loading yaml: {exc}')
            sys.exit(1)
    rmms = y['RMMs']
    for rmm in rmms:
        outyaml = yaml.safe_dump(rmms[rmm])
        print(outyaml)
        with open(f'./RMMs/{rmm}.yml', 'w') as f:
            f.write(outyaml)