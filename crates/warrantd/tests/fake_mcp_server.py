"""极简 MCP stdio server —— 只用于验证 warrantd proxy 的旁观与记账。

不是产品：只实现 tools/call 的应答，用来确认
「host → proxy → server → proxy → host」这条链路以及旁路记账是否成立。
用法见 kb/warrantd-洞2-MCP调用-2026-10-27.md。
"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    mid = msg.get("id")
    method = msg.get("method")
    if method == "tools/call":
        name = (msg.get("params") or {}).get("name", "?")
        resp = {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": "did:" + name}]}}
    elif method:
        resp = {"jsonrpc": "2.0", "id": mid, "result": {}}
    else:
        continue
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
