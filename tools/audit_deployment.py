"""Recompute deployment report checks against current executable inputs."""
import argparse
import json
from pathlib import Path
from .deployment_report import verify, render, CONTROL_NAMES
from .evidence import manifest


def main():
    p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args()
    root=Path(a.directory);v=json.loads((root/'deployment.json').read_text())
    verify(v,manifest())
    assert v['evidence_controls']==[{'name':n,'rejected':True} for n in CONTROL_NAMES]
    assert (root/'report.html').read_text()==render(v)
    print(json.dumps({'passed':True,'run_id':v['run_id'],'cases':len(v['cases']),'power_loss_tested':v['scope']['power_loss_tested']}))


if __name__=='__main__':main()
