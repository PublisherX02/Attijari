"""Sandboxed YARA signature scanning."""
import json
import sys
import glob

try:
    import yara

    content = open("/work/input", "rb").read()
    rule_files = glob.glob("/rules/*.yar") + glob.glob("/rules/*.yara")

    if not rule_files:
        json.dump({"tool": "yara", "status": "ok", "matches": [], "suspicious": False,
                    "note": "no rule files"}, sys.stdout)
        sys.exit(0)

    all_matches = []
    for rf in rule_files:
        try:
            rules = yara.compile(filepath=rf)
            for m in rules.match(data=content):
                all_matches.append({
                    "rule": m.rule,
                    "meta": m.meta,
                    "tags": m.tags,
                    "rule_file": rf.split("/")[-1],
                })
        except Exception as e:
            all_matches.append({"error": f"{rf}: {e}"})

    json.dump({
        "tool": "yara",
        "status": "ok",
        "matches": all_matches,
        "suspicious": any("rule" in m for m in all_matches),
    }, sys.stdout)
except Exception as e:
    json.dump({"tool": "yara", "status": "error", "error": str(e)}, sys.stdout)
