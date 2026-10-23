"""The Console AI helper: a small local service on your own computer that lets the Pegasus web page ask OCI Console AI.

It opens each client's OCI Console in a browser window on this computer. You sign in there yourself (MFA
included), once per client; the window then minimizes itself and stays signed in in the background while the
helper runs. The Pegasus page's Console AI chat window sends questions here; the helper types them into Console AI
and sends back the reply.

What stays where:
* Your OCI password and session never leave this computer, and Pegasus (the server) never sees them or the
  answers: the page in your browser talks straight to this helper.
* The helper listens on 127.0.0.1 only and answers only pages from the Pegasus address(es) given with --origin.
* It only types questions and reads replies. It never clicks anything in a reply, so it can't approve an action
  Console AI proposes.
"""
import json
import queue
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__

TENANCY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$", re.I)
REGION = re.compile(r"^([a-z]{2,4}-[a-z]+-\d{1,2})?$")
MAX_QUESTION = 2000


class Session:
    def __init__(self, tenancy, region, context, page):
        self.tenancy, self.region, self.context, self.page = tenancy, region, context, page
        self.state = "signing_in"            # signing_in | ready
        self.asking = False

    def view(self):
        return {"tenancy": self.tenancy, "region": self.region, "state": self.state, "asking": self.asking}


class Worker(threading.Thread):
    """Owns the browser. Playwright isn't thread-safe, so every browser action runs on this one thread; web
    requests hand it jobs and wait for the result."""

    def __init__(self, timeout=120, settle=5, debug=False, background="minimize"):
        super().__init__(daemon=True, name="console-ai-browser")
        self.jobs = queue.Queue()
        self.sessions = {}                   # tenancy (lower case) -> Session
        self.timeout, self.settle, self.background = timeout, settle, background
        self.debug_on = debug
        self.ready = threading.Event()
        self.failed = None

    # ---- called from web request threads -------------------------------------------------------------------
    def call(self, name, *args, wait=60):
        done, box = threading.Event(), {}
        self.jobs.put((name, args, done, box))
        if not done.wait(wait):
            raise TimeoutError("The browser is busy; try again in a moment.")
        if "error" in box:
            raise box["error"]
        return box["result"]

    def status(self):
        return [s.view() for s in list(self.sessions.values())]

    # ---- the browser thread --------------------------------------------------------------------------------
    def run(self):
        from playwright.sync_api import sync_playwright
        from . import console as C
        self.C = C
        try:
            with sync_playwright() as p:
                self.browser = p.chromium.launch(headless=False)
                self.ready.set()
                while True:
                    try:
                        name, args, done, box = self.jobs.get(timeout=1)
                    except queue.Empty:
                        self.tick()
                        continue
                    try:
                        box["result"] = getattr(self, "job_" + name)(*args)
                    except Exception as e:           # report it to the page; keep the helper running
                        box["error"] = e
                    done.set()
        except Exception as e:
            self.failed = e
            self.ready.set()

    def _window(self, page, state):
        """Minimize the window (run in the background) or bring it back to sign in."""
        try:
            cdp = page.context.new_cdp_session(page)
            wid = cdp.send("Browser.getWindowForTarget")["windowId"]
            if state == "show":
                cdp.send("Browser.setWindowBounds", {"windowId": wid, "bounds": {"windowState": "normal"}})
                if self.background == "offscreen":
                    cdp.send("Browser.setWindowBounds", {"windowId": wid, "bounds": {"left": 60, "top": 40}})
                page.bring_to_front()
            elif self.background == "offscreen":
                cdp.send("Browser.setWindowBounds", {"windowId": wid, "bounds": {"windowState": "normal"}})
                cdp.send("Browser.setWindowBounds", {"windowId": wid, "bounds": {"left": -4000, "top": 0}})
            else:
                cdp.send("Browser.setWindowBounds", {"windowId": wid, "bounds": {"windowState": "minimized"}})
            cdp.detach()
        except Exception as e:
            print(f"(couldn't {'show' if state == 'show' else 'hide'} the console window: {e})")

    def _alive(self, key):
        s = self.sessions.get(key)
        if s and s.page.is_closed():              # the person closed the window: that's a sign-out
            self.sessions.pop(key, None)
            try:
                s.context.close()
            except Exception:
                pass
            return None
        return s

    def _check_signed_in(self, s):
        if self.C.on_signin_page(s.page):
            return False
        try:
            s.page.wait_for_load_state("domcontentloaded", timeout=15000)
        except Exception:
            pass
        s.page.wait_for_timeout(1500)
        if self.C.on_signin_page(s.page):
            return False
        s.state = "ready"
        print(f"Signed in to {s.tenancy}; running it in the background.")
        self._window(s.page, "hide")
        return True

    def tick(self):
        for key in list(self.sessions):
            s = self._alive(key)
            if s and s.state == "signing_in":
                try:
                    self._check_signed_in(s)
                except Exception:
                    pass

    def job_signin(self, tenancy, region):
        key = tenancy.lower()
        s = self._alive(key)
        if s and s.region != region:              # region changed: start over in the right one
            self.job_signout(tenancy)
            s = None
        if s:
            if s.state == "ready" and self.C.on_signin_page(s.page):
                s.state = "signing_in"
            if s.state == "signing_in":
                self._window(s.page, "show")
            return s.view()
        ctx = self.browser.new_context(viewport={"width": 1400, "height": 860})
        page = ctx.new_page()
        s = self.sessions[key] = Session(tenancy, region, ctx, page)
        print(f"Opening the OCI Console for {tenancy}. Sign in in that window.")
        page.goto(self.C.console_url(tenancy, region), wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(2500)
        if not self._check_signed_in(s):
            self._window(page, "show")
        return s.view()

    def job_signout(self, tenancy):
        s = self.sessions.pop(tenancy.lower(), None)
        if s:
            try:
                s.context.close()
            except Exception:
                pass
        return {"tenancy": tenancy, "state": "signed_out"}

    def job_show(self, tenancy):
        s = self._alive(tenancy.lower())
        if s:
            self._window(s.page, "show")
        return s.view() if s else {"tenancy": tenancy, "state": "signed_out"}

    def job_ask(self, tenancy, question):
        s = self._alive(tenancy.lower())
        if not s:
            return {"need_signin": True}
        if s.state != "ready" or self.C.on_signin_page(s.page):
            s.state = "signing_in"
            self._window(s.page, "show")
            return {"need_signin": True}
        s.asking = True
        try:
            debug = self.C.Debug(self.debug_on, s.tenancy)
            answer = self.C.ask_in_page(s.page, question, self.timeout, self.settle, debug)
        finally:
            s.asking = False
        if answer is None:
            return {"error": "Couldn't find Console AI in the console. Is it available in this tenancy and region? "
                             "Restart the helper with --debug and send the debug folder."}
        if not answer:
            return {"error": "Console AI didn't answer in time. Try again, or ask a narrower question."}
        return {"answer": answer}


class Handler(BaseHTTPRequestHandler):
    server_version = "PegasusConsoleAI/" + __version__
    worker = None
    origins = ()

    def log_message(self, fmt, *a):          # quiet: don't print questions or answers to the console
        pass

    def _origin_ok(self):
        o = self.headers.get("Origin", "")
        return o if o in self.origins else None

    def _send(self, code, body, origin=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        origin = self._origin_ok()
        if not origin:
            return self._send(403, {"error": "This page isn't allowed to use the helper."})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")   # Chrome: public page -> localhost
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":                     # for a quick check from a terminal; says nothing about sessions
            return self._send(200, {"ok": True, "version": __version__})
        origin = self._origin_ok()
        if not origin:
            return self._send(403, {"error": "This page isn't allowed to use the helper. Start it with "
                                             "--origin set to your Pegasus address."})
        if path == "/status":
            w = self.worker
            return self._send(200, {"version": __version__, "browser": "failed" if w.failed else "ok",
                                    "sessions": w.status()}, origin)
        self._send(404, {"error": "not found"}, origin)

    def do_POST(self):
        origin = self._origin_ok()
        if not origin:
            return self._send(403, {"error": "This page isn't allowed to use the helper."})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._send(415, {"error": "JSON only"}, origin)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 20000)) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad request"}, origin)
        tenancy = str(body.get("tenancy") or "").strip()
        region = str(body.get("region") or "").strip()
        if not TENANCY.match(tenancy) or not REGION.match(region):
            return self._send(400, {"error": "Set this client's OCI tenancy and region in Pegasus first."}, origin)
        w = self.worker
        if w.failed:
            return self._send(500, {"error": f"The helper couldn't start a browser: {w.failed}. "
                                             "Run: python -m playwright install chromium"}, origin)
        path = urlparse(self.path).path
        try:
            if path == "/signin":
                return self._send(200, w.call("signin", tenancy, region, wait=90), origin)
            if path == "/show":
                return self._send(200, w.call("show", tenancy), origin)
            if path == "/signout":
                return self._send(200, w.call("signout", tenancy), origin)
            if path == "/ask":
                q = " ".join(str(body.get("question") or "").split())
                if not q:
                    return self._send(400, {"error": "Type a question."}, origin)
                if len(q) > MAX_QUESTION:
                    return self._send(400, {"error": f"Keep questions under {MAX_QUESTION} characters."}, origin)
                r = w.call("ask", tenancy, q, wait=w.timeout + 90)
                return self._send(200 if "error" not in r else 502, r, origin)
        except TimeoutError as e:
            return self._send(503, {"error": str(e)}, origin)
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"}, origin)
        self._send(404, {"error": "not found"}, origin)


def make_server(worker, origins, port=8765):
    origins = tuple(o.rstrip("/") for o in origins)
    handler = type("H", (Handler,), {"worker": worker, "origins": origins})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


def serve(origins, port=8765, timeout=120, settle=5, debug=False, background="minimize"):
    worker = Worker(timeout=timeout, settle=settle, debug=debug, background=background)
    worker.start()
    worker.ready.wait(60)
    if worker.failed:
        print(f"Couldn't start the browser: {worker.failed}\nRun: python -m playwright install chromium")
        return 2
    srv = make_server(worker, origins, port)
    print(f"Pegasus Console AI helper {__version__} is running on this computer (127.0.0.1:{port}).")
    print("Allowed Pegasus page(s): " + ", ".join(srv.RequestHandlerClass.origins))
    print("Open a client in Pegasus and click Console AI. Keep this window open; Ctrl+C stops the helper.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":                       # pragma: no cover
    raise SystemExit(serve(["https://pegasus.beastute.com"]))
