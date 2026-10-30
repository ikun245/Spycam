"""S1/S2/C1 验收脚本：回放 → 聚合 → 处置流转 → 去重率。"""
import io
import os
import sys
import time

import requests

BASE = os.environ.get("API_BASE_URL", "http://127.0.0.1:28765")
PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/syn_scan_smoke.pcap"

s = requests.Session()
s.headers["X-Requested-With"] = "spycam"  # 后端 CSRF 头校验
r = s.post(f"{BASE}/api/v1/auth/login", json={"username": "admin", "password": "change-me-admin"})
r.raise_for_status()

with open(PCAP, "rb") as fh:
    up = s.post(
        f"{BASE}/api/v1/pcaps",
        files={"file": (os.path.basename(PCAP), fh, "application/octet-stream")},
        data={"name": os.path.basename(PCAP)},
    )
up.raise_for_status()
pcap_id = up.json()["id"]
task = s.post(f"{BASE}/api/v1/replay-tasks", json={"pcap_id": pcap_id}).json()
print("task:", task["id"])

for _ in range(60):
    t = s.get(f"{BASE}/api/v1/replay-tasks/{task['id']}").json()
    if t["status"] in ("done", "failed"):
        break
    time.sleep(2)
print("status:", t["status"])

raw = s.get(f"{BASE}/api/v1/alerts", params={"task_id": task["id"], "limit": 500}).json()
print(f"raw alerts: {raw['total']}")

groups = s.get(f"{BASE}/api/v1/alert-groups", params={"limit": 100}).json()
print(f"groups: {groups.get('total')}")
if groups.get("items"):
    g = groups["items"][0]
    print("group sample:", {k: g.get(k) for k in ("id", "sid", "hit_count", "status")})
    if raw["total"]:
        print(f"dedup ratio: {raw['total']} raw / {groups['total']} groups")
    # S2 处置流转
    tr = s.patch(
        f"{BASE}/api/v1/alert-groups/{g['id']}/status",
        json={"status": "confirmed", "note": "validator smoke"},
    )
    print("triage:", tr.status_code, tr.text[:120])
    after = s.get(f"{BASE}/api/v1/alert-groups", params={"limit": 100}).json()
    st = [x["status"] for x in after.get("items", []) if x["id"] == g["id"]]
    print("status after triage:", st)
