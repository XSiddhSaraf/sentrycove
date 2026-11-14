# SignalMoat AI-triage demo (Datasette)

Puts SignalMoat in front of Datasette (open-source data publishing tool), sends
five kinds of traffic, and prints each alert with its AI triage note.

    export ANTHROPIC_API_KEY=sk-ant-...      # real Claude Haiku answers
    ./run_demo.sh

    ./run_demo.sh --offline                  # no key: llm_standin.py returns fixed, hand-written replies

Files: policy.yaml (SignalMoat policy), attacks.sh (the traffic), llm_standin.py
(offline stand-in that also records the exact LLM request to llm_requests.jsonl).
In attacks.sh, X-Forwarded-For and cf-ja4 stand in for the TLS terminator
(nginx / Cloudflare) that writes them in production.
