"""Minimal FastAPI app protected by SentryCove.

Run (from the repository root):
    pip install -e ".[dev]" uvicorn
    uvicorn examples.fastapi_app:app --port 8000

Then try:
    curl -X POST localhost:8000/contact -A "python-requests/2.32"   # rule-match alert
    curl localhost:8000/.env                                       # honeypot alert
    for i in $(seq 10); do curl -s -X POST localhost:8000/login >/dev/null; done  # brute-force alert
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request

from sentrycove import SentryCove

logging.basicConfig(level=logging.INFO)
POLICY = Path(__file__).with_name("sentrycove.yaml")


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await app.aclose()  # flush pending alerts and close HTTP clients on shutdown


api = FastAPI(lifespan=lifespan)


@api.get("/")
def home(request: Request):
    # Handlers can see who SentryCove thinks is calling.
    return {"you_are": request.state.sentrycove.label}


@api.post("/contact")
def contact():
    return {"received": True}


@api.post("/login")
def login():
    raise HTTPException(status_code=401, detail="invalid credentials")


# The one line that matters. (api.add_middleware(SentryCove, config=POLICY) also
# works; wrapping explicitly gives you a handle for clean shutdown.)
app = SentryCove(api, config=POLICY)
