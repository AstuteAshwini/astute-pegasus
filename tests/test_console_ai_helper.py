"""The Console AI helper's web side: only the Pegasus page may use it, input is checked, and answers come back."""
import sys
import threading
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "console-ai"))
from pegasus_console_ai import helper  # noqa: E402

ORIGIN = "https://pegasus.example.com"


class FakeWorker:
    failed = None
    timeout = 5

    def __init__(self):
        self.calls = []

    def status(self):
        return [{"tenancy": "miracostaoci", "region": "us-phoenix-1", "state": "ready", "asking": False}]

    def call(self, name, *args, wait=60):
        self.calls.append((name, args))
        if name == "ask":
            return {"answer": "No stopped compute instances were found."}
        return {"tenancy": args[0], "state": "signing_in"}


@pytest.fixture()
def helper_url():
    w = FakeWorker()
    srv = helper.make_server(w, [ORIGIN + "/"], port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", w
    srv.shutdown()


def test_only_the_pegasus_page_may_use_it(helper_url):
    url, w = helper_url
    assert requests.get(url + "/health").json()["ok"]
    assert requests.get(url + "/status").status_code == 403
    assert requests.get(url + "/status", headers={"Origin": "https://evil.example"}).status_code == 403
    r = requests.post(url + "/ask", json={"tenancy": "miracostaoci", "question": "hi"},
                      headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and not w.calls
    r = requests.options(url + "/ask", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                                                 "Access-Control-Request-Private-Network": "true"})
    assert r.status_code == 204 and r.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert r.headers["Access-Control-Allow-Private-Network"] == "true"
    r = requests.get(url + "/status", headers={"Origin": ORIGIN})
    assert r.ok and r.json()["sessions"][0]["state"] == "ready"
    assert r.headers["Access-Control-Allow-Origin"] == ORIGIN


def test_asking_and_signing_in(helper_url):
    url, w = helper_url
    h = {"Origin": ORIGIN}
    r = requests.post(url + "/ask", headers=h, json={"tenancy": "miracostaoci", "region": "us-phoenix-1",
                                                     "question": "  which instances\n are stopped? "})
    assert r.ok and r.json()["answer"].startswith("No stopped")
    assert w.calls[-1] == ("ask", ("miracostaoci", "which instances are stopped?"))
    assert requests.post(url + "/signin", headers=h, json={"tenancy": "miracostaoci", "region": ""}).ok
    # checked before anything reaches the browser
    for body in ({"tenancy": "", "question": "x"}, {"tenancy": "a b", "question": "x"},
                 {"tenancy": "t", "region": "javascript:1", "question": "x"}, {"tenancy": "t", "question": " "},
                 {"tenancy": "t", "question": "x" * 2001}):
        assert requests.post(url + "/ask", headers=h, json=body).status_code == 400
    r = requests.post(url + "/ask", headers=dict(h, **{"Content-Type": "text/plain"}), data='{"tenancy":"t"}')
    assert r.status_code == 415
    assert len(w.calls) == 2
