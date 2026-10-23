"""python -m pegasus_console_ai            start the helper for the Pegasus web page (the usual way)
python -m pegasus_console_ai chat ...   ask Console AI from this terminal instead (no Pegasus needed)"""
import argparse
import sys

from . import helper


def chat(a):
    from playwright.sync_api import sync_playwright
    from . import console as C
    debug = C.Debug(a.debug, a.tenancy)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_context(viewport={"width": 1400, "height": 860}).new_page()
        page.goto(C.console_url(a.tenancy, a.region), wait_until="domcontentloaded", timeout=60000)
        try:
            if not C.wait_until_signed_in(page, debug):
                return 2
            print("Signed in. Type a question and press Enter; an empty line or Ctrl+C ends the session.")
            while True:
                try:
                    q = input("\nQuestion> ").strip()
                except (EOFError, KeyboardInterrupt):
                    return 0
                if not q:
                    return 0
                if C.on_signin_page(page) and not C.wait_until_signed_in(page, debug):
                    return 2
                answer = C.ask_in_page(page, q, a.timeout, a.settle, debug)
                if answer is None:
                    return 3
                print("\n" + (answer or "No answer came back in time. Try --timeout 180."))
        finally:
            browser.close()


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m pegasus_console_ai", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="start the helper (the default)")
    c = sub.add_parser("chat", help="ask Console AI from this terminal")
    c.add_argument("--tenancy", required=True)
    c.add_argument("--region", default="")
    for x in (p, s, c):
        x.add_argument("--timeout", type=int, default=120, help="seconds to wait for each answer")
        x.add_argument("--settle", type=float, default=5, help="seconds an answer must stop changing")
        x.add_argument("--debug", action="store_true", help="save screenshots and page structure for fixing")
    for x in (p, s):
        x.add_argument("--origin", action="append", help="the Pegasus address allowed to use this helper "
                       "(default https://pegasus.beastute.com); repeat for more than one")
        x.add_argument("--port", type=int, default=8765)
        x.add_argument("--background", choices=("minimize", "offscreen"), default="minimize",
                       help="how signed-in console windows are kept out of the way")
    a = p.parse_args(argv)
    if a.cmd == "chat":
        return chat(a)
    return helper.serve(a.origin or ["https://pegasus.beastute.com"], a.port, a.timeout, a.settle, a.debug,
                        a.background)


if __name__ == "__main__":
    sys.exit(main())
