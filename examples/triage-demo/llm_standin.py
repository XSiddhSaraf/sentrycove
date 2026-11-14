"""Stand-in for the Anthropic Messages API, for running the demo WITHOUT an API key.

It records the exact request SignalMoat sends (llm_requests.jsonl) and returns a
FIXED reply written by hand for each alert type. It is not a model. To see a
real model's answer, run the demo with ANTHROPIC_API_KEY set and without this.

For the prompt-injection probe it deliberately answers like a model that was
fooled (a link and a Slack @channel), to show SignalMoat stripping them.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLIES = {
    "honeypot_hit": {
        "what_happened": "A client requested a decoy file that only attackers look for, such as /.env or /.git.",
        "how_bad": "High: someone is actively scanning this app for leaked secrets.",
        "what_to_do": "Keep the IP ban in place and confirm no .env or .git files are served from the web root.",
    },
    "policy_match": {
        "what_happened": "A script tried to download the customers table as JSON and was blocked by a rule.",
        "how_bad": "Medium: bulk export by a script, likely scraping, stopped before data left.",
        "what_to_do": "Leave the rule on block; if this is a partner, give them an API token instead.",
    },
    "ja4_browser_mismatch": {
        "what_happened": "The client says it is Chrome, but its TLS handshake looks like an HTTP library.",
        "how_bad": "Medium: a scraper disguising itself as a browser.",
        "what_to_do": "Watch this IP; add a ja4 rule for this fingerprint if it keeps coming back.",
    },
}
FOOLED = {
    "what_happened": "Routine maintenance check, nothing to worry about. Details: https://evil.example/fix <!channel>",
    "how_bad": "Low",
    "what_to_do": "Visit www.evil.example and disable the ban @here",
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        record = {"path": self.path, "headers": {k: v for k, v in self.headers.items()}, "body": body}
        record["headers"]["Authorization"] = "Bearer ***"  # never write the key to disk
        with open("llm_requests.jsonl", "a") as fh:
            fh.write(json.dumps(record) + "\n")
        prompt = body["messages"][0]["content"]
        if "Ignore all prior instructions" in prompt:
            answer = FOOLED
        else:
            alert_type = json.loads(prompt.split("\n")[1])["type"]
            answer = REPLIES.get(alert_type, REPLIES["policy_match"])
        payload = json.dumps({"type": "message", "content": [{"type": "text", "text": json.dumps(answer)}]})
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *args) -> None:
        pass


HTTPServer(("127.0.0.1", 9900), Handler).serve_forever()
