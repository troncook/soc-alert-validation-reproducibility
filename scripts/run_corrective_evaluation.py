from __future__ import annotations
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

def main():
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/'src'))
    from soc_validation_experiment.corrective_evaluation import run
    p=argparse.ArgumentParser(description='Run the fixed September 5 corrective protocol locally; no hosted services.')
    p.add_argument('--config',default='config/cicids2017_full_candidate.toml')
    p.add_argument('--protocol',default='docs/remediation_protocol_20260905.md')
    p.add_argument('--synthetic',action='store_true')
    p.add_argument('--conditions',nargs='+')
    p.add_argument('--output')
    a=p.parse_args()
    output=root/(a.output or f'outputs/corrective_evaluation/{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}')
    result=run(root,root/a.config,output,root/a.protocol,a.synthetic,a.conditions)
    print(f'Completed: {result}')

if __name__=='__main__':
    main()
