#!/usr/bin/env bash
# SignalMoat AI-triage demo: Datasette (open source) behind SignalMoat.
#
#   export ANTHROPIC_API_KEY=sk-ant-...   # real model (Claude Haiku)
#   ./run_demo.sh
#
#   ./run_demo.sh --offline               # no key: local stand-in returns fixed replies
#
# Needs Python 3.10+ and curl. Uses ports 8001 (Datasette), 8080 (SignalMoat), 9900 (stand-in).
set -euo pipefail
cd "$(dirname "$0")"

OFFLINE=0; [[ "${1:-}" == "--offline" ]] && OFFLINE=1
if [[ $OFFLINE -eq 0 && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "Set ANTHROPIC_API_KEY, or run with --offline." >&2; exit 2
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q datasette \
    "signalmoat[server] @ git+https://github.com/XSiddhSaraf/signalmoat@roadmap-redis-websocket-ja4-triage"
fi
PY=.venv/bin/python; BIN=.venv/bin

$PY - <<'EOF'
import sqlite3
db = sqlite3.connect("shop.db")
db.executescript("""
drop table if exists customers;
create table customers (id integer primary key, name text, city text, plan text);
insert into customers (name, city, plan) values
 ('Asha Rao','Pune','pro'),('Ravi Kumar','Mumbai','free'),('Meera Iyer','Bengaluru','pro'),
 ('Karan Shah','Ahmedabad','team'),('Neha Joshi','Pune','free');
""")
db.commit()
EOF

POLICY=policy.yaml
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

$BIN/datasette serve shop.db -h 127.0.0.1 -p 8001 >datasette.log 2>&1 & pids+=($!)
if [[ $OFFLINE -eq 1 ]]; then
  $PY llm_standin.py & pids+=($!)
  $PY -c "import pathlib; s=pathlib.Path('policy.yaml').read_text(); pathlib.Path('policy.offline.yaml').write_text(s.replace('    timeout_seconds: 15', '    timeout_seconds: 15\n    base_url: http://127.0.0.1:9900'))"
  POLICY=policy.offline.yaml
  export ANTHROPIC_API_KEY=offline
fi
rm -f signalmoat.log llm_requests.jsonl
$BIN/signalmoat proxy --upstream http://127.0.0.1:8001 --config "$POLICY" --port 8080 >signalmoat.log 2>&1 & pids+=($!)
sleep 3

echo "== Traffic =="
./attacks.sh
echo; echo "== Waiting for triage notes =="; sleep 20

$PY - <<'EOF'
import json
for line in open("signalmoat.log"):
    if "triage withheld" in line or "triage failed" in line or "triage timed out" in line:
        print("LOG:", line.split(" WARNING ", 1)[-1].strip())
    if "signalmoat alert" not in line:
        continue
    a = json.loads(line.split("signalmoat alert ", 1)[1])
    print(f"\n[{a['severity'].upper()}] {a['title']}")
    print(f"  {a['method']} {a['path']}  from {a['client_ip']}  ->  {a['action_taken']}")
    print(f"  {a['detail'][:140]}")
    for label, key in (("What happened", "what_happened"), ("How bad", "how_bad"), ("What to do", "what_to_do")):
        if a.get("triage"):
            print(f"  AI {label}: {a['triage'][key]}")
    if not a.get("triage"):
        print("  (no AI note)")
EOF
echo; echo "Full logs: signalmoat.log"
echo "The app is still running. Open in your browser:"
echo "  http://127.0.0.1:8080/shop/customers   (through SignalMoat)"
echo "  http://127.0.0.1:8001/shop/customers   (Datasette directly)"
read -r -p "Press Enter to stop the servers... " _
