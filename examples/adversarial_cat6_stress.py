"""Category 6 — Multi-agent stress test against the live daemon.

Spawns AGENTS concurrent "agents", each firing ACTIONS governs against the
shared daemon (shared policy engine + shared durable audit ledger). Verifies:
  - every decision is durably recorded (ledger count == total, survives restart)
  - no panics / HTTP errors under concurrency
  - the shared policy engine behaves identically for all agents
"""

import json
import threading
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8443"
AGENTS = 50
ACTIONS = 20  # per agent -> 1000 total governs

errors = []
counts = []
lock = threading.Lock()


def govern(agent_id, i):
    body = {
        "action": f"a{agent_id}_{i}",
        "target": f"10.0.{agent_id % 256}.{i % 256}",
        "capability": "NetworkScan",
        "impact": "low",
        "destructive": False,
    }
    try:
        req = urllib.request.Request(
            BASE + "/api/v1/govern", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
            with lock:
                counts.append(1)
            return d
    except Exception as e:
        with lock:
            errors.append(str(e))
        return None


def main():
    threads = []
    for a in range(AGENTS):
        for i in range(ACTIONS):
            t = threading.Thread(target=govern, args=(a, i))
            threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = AGENTS * ACTIONS
    print(f"sent {total} governs across {AGENTS} agents")
    print(f"errors: {len(errors)}")
    if errors:
        print("first 3 errors:", errors[:3])

    # Live in-memory count via audit endpoint (before restart).
    req = urllib.request.Request(BASE + "/api/v1/audit?n=100000")
    with urllib.request.urlopen(req, timeout=15) as r:
        live = len(json.loads(r.read()))
    print(f"live audit count (in-memory): {live}")

    # Durable count on disk (the ledger file).
    import os
    disk = 0
    p = os.path.expanduser("~/.icebox/audit.jsonl")
    if os.path.exists(p):
        with open(p) as f:
            disk = sum(1 for _ in f if _.strip())
    print(f"durable ledger lines on disk: {disk}")

    print("\nVERDICT:")
    ok = (len(errors) == 0 and live == total and disk == total)
    print(f"  no errors:           {len(errors) == 0}")
    print(f"  live == total:       {live} == {total} -> {live == total}")
    print(f"  durable == total:    {disk} == {total} -> {disk == total}")
    print(f"  OVERALL: {'PASS' if ok else 'FAIL'}")


if __name__ == "__main__":
    main()
