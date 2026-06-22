"""Sandboxed OLE/VBA macro extraction."""
import json
import sys
import os

try:
    from oletools.olevba import VBA_Parser
    from oletools import oleid

    content = open("/work/input", "rb").read()
    filename = os.environ.get("ORIGINAL_NAME", "file.bin")

    result = {"tool": "oletools", "status": "ok", "macros": [], "ole_indicators": [], "suspicious": False}

    # OLE ID
    try:
        oid = oleid.OleID(data=content)
        indicators = oid.check()
        for ind in indicators:
            entry = {"name": ind.name, "value": str(ind.value)}
            if hasattr(ind, "risk"):
                entry["risk"] = str(ind.risk)
                if str(ind.risk).lower() in ("high", "medium"):
                    result["suspicious"] = True
            result["ole_indicators"].append(entry)
    except Exception as e:
        result["ole_indicators"].append({"error": str(e)})

    # VBA macros
    try:
        vba = VBA_Parser(filename, data=content)
        if vba.detect_vba_macros():
            result["suspicious"] = True
            for vba_type, stream, sub, code in vba.extract_macros():
                result["macros"].append({
                    "type": str(vba_type),
                    "stream": str(stream),
                    "name": str(sub),
                    "code_preview": (code[:500] if code else ""),
                })
        vba.close()
    except Exception as e:
        result["macros"].append({"error": str(e)})

    json.dump(result, sys.stdout)
except Exception as e:
    json.dump({"tool": "oletools", "status": "error", "error": str(e)}, sys.stdout)
