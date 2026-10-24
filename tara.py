#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

LEVELS=((20,"CRITICAL"),(12,"HIGH"),(6,"MEDIUM"),(0,"LOW"))

def analyze(model):
    results=[]
    for index,threat in enumerate(model.get("threats",[])):
        required=("id","asset","severity","likelihood"); missing=[key for key in required if key not in threat]
        if missing: raise ValueError(f"threats[{index}] missing {', '.join(missing)}")
        severity=int(threat["severity"]); likelihood=int(threat["likelihood"])
        if not 1<=severity<=5 or not 1<=likelihood<=5: raise ValueError(f"threat {threat['id']}: severity and likelihood must be 1..5")
        score=severity*likelihood; level=next(label for minimum,label in LEVELS if score>=minimum)
        results.append({**threat,"score":score,"risk":level,"priority":"P0" if score>=20 else "P1" if score>=12 else "P2"})
    return sorted(results,key=lambda item:(-item["score"],item["id"]))

def main(argv=None):
    parser=argparse.ArgumentParser(description="Score a small automotive TARA model"); parser.add_argument("model",type=Path); parser.add_argument("-o","--output",type=Path); args=parser.parse_args(argv)
    try: results=analyze(json.loads(args.model.read_text(encoding="utf-8")))
    except (OSError,json.JSONDecodeError,ValueError) as exc: print(f"error: {exc}"); return 2
    payload=json.dumps({"results":results},indent=2,ensure_ascii=False)+"\n"
    if args.output: args.output.write_text(payload,encoding="utf-8")
    else: print(payload,end="")
    return 0

if __name__=="__main__": raise SystemExit(main())
