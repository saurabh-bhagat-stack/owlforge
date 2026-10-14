"""mitmproxy addon: append one compact JSON record per response to a JSONL file.
The agentd /proxy/flows endpoint reads this back for the agent to inspect."""

import json
import os
import time

PATH = os.environ.get("OWLFORGE_FLOWLOG", "/workspace/.owlforge/flows.jsonl")
os.makedirs(os.path.dirname(PATH), exist_ok=True)


def response(flow):
    try:
        rec = {
            "ts": round(time.time(), 3),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "content_type": flow.response.headers.get("content-type", ""),
            "resp_len": len(flow.response.raw_content or b""),
        }
        with open(PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass
