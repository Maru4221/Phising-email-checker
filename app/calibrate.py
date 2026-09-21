from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.main import analyze_bytes
from app.score import Verdict, compute_score, finding_from_dict

POSITIVE_VERDICTS = {Verdict.SUSPICIOUS, Verdict.MALICIOUS}

def collect_samples(root: Path) -> List[Tuple[Path, str]]:
    samples: List[Tuple[Path, str]] = []
    if not root.exists():
        return samples

    phish_dir, legit_dir = root / "phish", root / "legit"
    for path in sorted(root.rglob("*.eml")) + sorted(root.rglob("*.msg")) + sorted(root.rglob("*.txt")):
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix().lower()
        if rel.startswith("phish/"):
            label = "phish"
        elif rel.startswith("legit/"):
            label = "legit"
        elif path.parent in (phish_dir, legit_dir):
            label = path.parent.name
        else:
            name = path.name.lower()
            if name.startswith("phish_"):
                label = "phish"
            elif name.startswith("legit_"):
                label = "legit"
            else:
                continue
        samples.append((path, label))
    return samples

def evaluate_file(path: Path, label: str,
                  suspicious_min: Optional[int] = None,
                  malicious_min: Optional[int] = None) -> Dict:
    try:
        raw = path.read_bytes()
        analysis = analyze_bytes(raw)
    except Exception as exc:
        return {"path": path, "label": label, "outcome": "error",
                "error": f"{type(exc).__name__}: {exc}"}

    findings = [finding_from_dict(f) for f in analysis["findings"]]
    score_val = sum(f.severity.weight for f in findings)

    if suspicious_min is None or malicious_min is None:
        result = compute_score(findings)
        verdict = result.verdict
    else:
        from app.score import get_thresholds
        default_s, _default_m = get_thresholds()
        s = suspicious_min if suspicious_min is not None else default_s
        if score_val >= (malicious_min if malicious_min is not None else s + 1):
            verdict = Verdict.MALICIOUS
        elif score_val >= s:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

    flagged = verdict in POSITIVE_VERDICTS
    if label == "phish":
        outcome = "TP" if flagged else "FN"
    else:
        outcome = "FP" if flagged else "TN"

    return {
        "path": path, "label": label, "outcome": outcome,
        "verdict": verdict.value, "score": score_val,
        "findings": [f.title for f in findings],
        "top_findings": analysis["findings"][:6],
    }

def compute_metrics(results: List[Dict]) -> Dict[str, float]:
    tp = sum(1 for r in results if r["outcome"] == "TP")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    errors = sum(1 for r in results if r["outcome"] == "error")

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "errors": errors,
        "precision": precision, "recall": recall,
        "f1": f1, "accuracy": (tp + tn) / total if total else 0.0,
    }

def print_report(results: List[Dict], metrics: Dict[str, float]) -> None:
    width = max((len(str(r["path"])) for r in results), default=20)

    print(f"\n{'RESULT':<8}{'LABEL':<7}{'VERDICT':<11}{'SCORE':<6}FILE")
    print("-" * (width + 40))
    order = {"FN": 0, "FP": 1, "error": 2, "TP": 3, "TN": 4}
    for r in sorted(results, key=lambda x: order.get(x["outcome"], 9)):
        line = f"{r['outcome']:<8}{r['label']:<7}{r.get('verdict', '?'):<11}{r.get('score', '?'):<6}{r['path']}"
        print(line)
        if r["outcome"] in ("FN", "FP", "error"):
            why = r.get("error") or "; ".join(r.get("findings", [])) or "no findings at all"
            print(f"{'':<32}-> {why[:120]}")

    print("\n== Metrics (phishing = positive) ==")
    print(f"  TP {metrics['tp']}   FP {metrics['fp']}   TN {metrics['tn']}   FN {metrics['fn']}"
          + (f"   errors {metrics['errors']}" if metrics["errors"] else ""))
    print(f"  precision {metrics['precision']:.0%}   recall {metrics['recall']:.0%}   "
          f"F1 {metrics['f1']:.2f}   accuracy {metrics['accuracy']:.0%}")

    if metrics["fn"]:
        print("\n  False negatives (missed phish) — raise weights or add heuristics:")
        for r in results:
            if r["outcome"] == "FN":
                print(f"    - {r['path']} (score {r.get('score')})")
    if metrics["fp"]:
        print("\n  False positives (legit flagged) — look for over-eager rules:")
        for r in results:
            if r["outcome"] == "FP":
                print(f"    - {r['path']} (score {r.get('score')}): {'; '.join(r.get('findings', [])[:4])}")

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Batch-score labeled .eml samples and report calibration metrics.")
    ap.add_argument("--dir", default="samples", help="sample root folder (default: samples)")
    ap.add_argument("--suspicious-min", type=int, default=None,
                    help="candidate SUSPICIOUS cut point (default: engine value)")
    ap.add_argument("--malicious-min", type=int, default=None,
                    help="candidate MALICIOUS cut point (default: engine value)")
    ap.add_argument("--csv", action="store_true", help="print machine-readable CSV instead")
    args = ap.parse_args(argv)

    root = Path(args.dir)
    samples = collect_samples(root)
    if not samples:
        print(f"No labeled samples found under {root}/.")
        print("Expected samples/phish/*.eml and samples/legit/*.eml (or phish_/legit_ filename prefixes).")
        return 1

    results = [evaluate_file(p, label, args.suspicious_min, args.malicious_min)
               for p, label in samples]
    metrics = compute_metrics(results)

    if args.csv:
        print("file,label,outcome,verdict,score")
        for r in results:
            print(f"{r['path']},{r['label']},{r['outcome']},{r.get('verdict', 'error')},{r.get('score', '')}")
    else:
        cut = f" (cut points: suspicious>={args.suspicious_min or 'engine default'}," \
              f" malicious>={args.malicious_min or 'engine default'})"
        print(f"Scoring {len(results)} samples from {root}/{cut}")
        print_report(results, metrics)

    return 0

if __name__ == "__main__":
    sys.exit(main())
