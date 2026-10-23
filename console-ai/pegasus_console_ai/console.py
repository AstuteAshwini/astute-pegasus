"""Drive OCI Console AI in a browser the way a person would: find its panel, type a question, read the reply.

Oracle publishes no API for Console AI, so this reads the Console page itself. It never clicks anything in a
reply, so it can't approve an action Console AI proposes. If Oracle changes the page, debug snapshots (--debug)
show what it saw so the selectors can be fixed.
"""
import os
import re
import time
from pathlib import Path

from playwright.sync_api import TimeoutError as PWTimeout

SIGNIN_HOSTS = re.compile(r"(identity\.oraclecloud\.com|login\.[a-z0-9-]+\.oraclecloud\.com|/signin|/login)", re.I)
AI_BUTTON_NAMES = re.compile(r"^(ai|console ai|ask ai|open console ai|ask console ai)$", re.I)
BUSY_WORDS = re.compile(r"\b(thinking|generating|working on it|analyzing|searching)\b", re.I)


def console_url(tenancy, region):
    if os.environ.get("CONSOLE_AI_TEST_URL"):             # for testing against a mock page only
        return os.environ["CONSOLE_AI_TEST_URL"]
    return f"https://cloud.oracle.com/?tenant={tenancy}" + (f"&region={region}" if region else "")


def all_frames(page):
    return [page.main_frame] + [f for f in page.frames if f != page.main_frame]


def on_signin_page(page):
    """True on Oracle's sign-in page, judged by its address or by what's on it."""
    if SIGNIN_HOSTS.search(page.url):
        return True
    for f in all_frames(page):
        try:
            if f.locator("input[type=password]").filter(visible=True).count():
                return True
            if f.get_by_text(re.compile(r"Oracle Cloud Account Sign In|Sign in to Oracle Cloud", re.I)).count():
                return True
        except Exception:
            continue
    return False


class Debug:
    def __init__(self, on, client):
        self.on, self.n = on, 0
        self.dir = Path.cwd() / f"console_ai_debug_{client}_{time.strftime('%Y%m%d-%H%M%S')}"

    def snap(self, page, label):
        if not self.on:
            return
        self.dir.mkdir(exist_ok=True)
        self.n += 1
        base = self.dir / f"{self.n:02d}_{label}"
        try:
            page.screenshot(path=f"{base}.png", full_page=False)
            Path(f"{base}_url.txt").write_text(page.url.split("?")[0], encoding="utf-8")
            parts = []
            for f in all_frames(page):
                try:
                    parts.append(f"=== frame {f.url.split('?')[0]}\n" + f.locator("body").aria_snapshot())
                except Exception as e:
                    parts.append(f"=== frame {f.url.split('?')[0]}: {e}")
            Path(f"{base}_structure.txt").write_text("\n\n".join(parts)[:400000], encoding="utf-8")
        except Exception as e:                      # debugging must never stop the run
            print(f"(debug snapshot failed: {e})")


def find_ai_button(page):
    for f in all_frames(page):
        for loc in (f.get_by_role("button", name=AI_BUTTON_NAMES),
                    f.locator("button[aria-label*='Console AI' i], [role=button][aria-label*='Console AI' i]"),
                    f.locator("button[aria-label='AI'], button[title*='AI' i]")):
            try:
                if loc.count() and loc.first.is_visible():
                    return loc.first
            except Exception:
                continue
    return None


def find_question_box(page):
    """The Console AI text box: a visible textbox inside something that mentions Console AI, else the last one."""
    for f in all_frames(page):                  # the real Console AI panel: complementary "Console AI" > textbox
        for loc in (f.get_by_role("complementary", name=re.compile(r"console ai", re.I)).get_by_role("textbox"),
                    f.get_by_role("textbox", name=re.compile(r"what would you like to do", re.I))):
            try:
                for i in range(loc.count()):
                    el = loc.nth(i)
                    if el.is_visible() and el.is_editable():
                        return el
            except Exception:
                continue
    candidates = []
    for f in all_frames(page):
        for loc in (f.get_by_role("textbox"), f.locator("textarea, [contenteditable=true]")):
            try:
                for i in range(loc.count()):
                    el = loc.nth(i)
                    if el.is_visible() and el.is_editable():
                        candidates.append(el)
            except Exception:
                continue
    for el in candidates:
        try:
            near = el.evaluate("e => { let n = e; for (let i = 0; i < 8 && n.parentElement; i++) n = n.parentElement;"
                               " return (n ? n.innerText : '').slice(0, 4000) }")
            ph = (el.get_attribute("placeholder") or "") + " " + (el.get_attribute("aria-label") or "")
            if re.search(r"console ai|ask|question|how can i help", near + " " + ph, re.I) and \
                    not re.search(r"search resources", ph, re.I):
                return el
        except Exception:
            continue
    return None


# Text of an element as a person sees it, including what plain innerText leaves out: open shadow DOM (where
# Console AI draws its cards, e.g. "OCI network path check") and embedded frames, which are left as markers
# (\u0001<n>\u0001) for Python to fill in, since a frame's text can only be read through Playwright.
DEEP_TEXT = r"""function deepText(root, frames) {
  const out = [];
  const BLOCK = /^(block|flex|grid|list-item|table|table-row|table-caption|flow-root)$/;
  const walk = n => {
    if (n.nodeType === 3) { out.push(n.nodeValue.replace(/\s+/g, ' ')); return; }
    if (n.nodeType !== 1 && n.nodeType !== 11) return;
    let disp = '';
    if (n.nodeType === 1) {
      const tag = n.tagName;
      if (/^(SCRIPT|STYLE|TEMPLATE|NOSCRIPT|SVG)$/i.test(tag) || n.hidden) return;
      const cs = getComputedStyle(n);
      if (cs.display === 'none' || cs.visibility === 'hidden') return;
      disp = cs.display;
      if (tag === 'BR') { out.push('\n'); return; }
      if (tag === 'IFRAME' || tag === 'FRAME') {
        n.setAttribute('data-pg-frame', frames.length); out.push('\n\u0001' + frames.length + '\u0001\n');
        frames.push(n.getAttribute('title') || ''); return;
      }
      if (tag === 'SLOT') { (n.assignedNodes({flatten: true}).length ? n.assignedNodes({flatten: true}) : [...n.childNodes]).forEach(walk); return; }
      if (BLOCK.test(disp)) out.push('\n');
      if (disp === 'table-cell') out.push('\t');
    }
    const kids = n.nodeType === 1 && n.shadowRoot ? [...n.shadowRoot.childNodes] : [...n.childNodes];
    kids.forEach(walk);
    if (BLOCK.test(disp)) out.push('\n');
  };
  walk(root);
  return out.join('').split('\n').map(l => l.replace(/[ ]+/g, ' ').replace(/^ | $/g, '')).join('\n');
}"""

COUNT_QUESTION = r"""(log, q) => { """ + DEEP_TEXT + r"""
  return deepText(log, []).toLowerCase().split(q.toLowerCase()).length - 1 }"""

FRAME_TEXT = r"""() => { """ + DEEP_TEXT + r""" return deepText(document.body, []) }"""

# The reply starts after our question's own echo: occurrence number `seen` (0-based) of the question in the log,
# counting the times it was already there before we asked. Later copies (e.g. Console AI quoting it) are answer.
READ_ANSWER = r"""(log, [q, seen]) => { """ + DEEP_TEXT + r"""
  // Console AI is busy while it shows "Cancel request", a "Thinking" status, or a disabled text box.
  const panel = log.closest('[role=complementary],aside') || log.parentElement;
  const label = el => ((el.getAttribute('aria-label') || '') + ' ' + (el.innerText || '')).trim();
  const busy = [...panel.querySelectorAll('button')].some(b => /cancel request|stop/i.test(label(b)))
            || [...panel.querySelectorAll('[role=status]')].some(s => /thinking|working|generating/i.test(label(s)))
            || [...panel.querySelectorAll('textarea,input,[role=textbox]')].some(t => t.disabled || t.getAttribute('aria-disabled') === 'true');
  const frames = [];
  let text = deepText(log, frames);
  const low = text.toLowerCase(), ql = q.toLowerCase();
  let i = -1;
  for (let k = 0; k <= seen; k++) { i = low.indexOf(ql, i + 1); if (i < 0) return {busy, text: '', frames}; }
  text = text.slice(i + q.length);
  // Drop the "Thinking" steps (the group holding the Thinking button), status lines and button labels.
  const drop = [];
  for (const b of log.querySelectorAll('button')) {
    if (/^thinking/i.test((b.innerText || b.getAttribute('aria-label') || '').trim()))
      drop.push(deepText(b.closest('[role=group]') || b.parentElement, []));
  }
  for (const st of log.querySelectorAll('[role=status]')) drop.push(deepText(st, []));
  for (const d of drop) if (d.trim()) text = text.split(d.trim()).join('\n');
  const skip = new Set([...log.querySelectorAll('button')].map(b => (b.innerText || '').trim()).filter(Boolean));
  for (const b of skip) if (b.length > 3) text = text.split(b).join('\n');
  text = text.split('\n').map(l => l.trim()).filter(l => l && !skip.has(l) && !/^thinking$/i.test(l)).join('\n');
  return {busy, text, frames};
}"""


def fill_frames(log, text, titles):
    """Put the text of each embedded frame (a card Console AI drew in its own frame) where it sits in the reply."""
    def frame_text(n):
        try:
            frame = log.locator(f'[data-pg-frame="{n}"]').element_handle(timeout=2000).content_frame()
            body = frame.evaluate(FRAME_TEXT) if frame else ""
        except Exception:
            body = ""
        body = "\n".join(line for line in (x.strip() for x in body.split("\n")) if line)
        title = titles[n] if n < len(titles) else ""
        return "\n".join(x for x in (title, body) if x)
    return re.sub("\u0001(\\d+)\u0001", lambda m: frame_text(int(m.group(1))), text)


def console_ai_log(page):
    """The conversation log inside the Console AI side panel (role=complementary named "Console AI")."""
    for f in all_frames(page):
        try:
            panel = f.get_by_role("complementary", name=re.compile(r"console ai", re.I))
            if panel.count():
                log = panel.first.get_by_role("log")
                if log.count():
                    return log.last
        except Exception:
            continue
    return None


def read_answer(page, box, question, before, seen=0):
    """The reply after the question: from the Console AI log if there is one, else from the panel's text."""
    log = console_ai_log(page)
    if log is not None:
        try:
            r = log.evaluate(READ_ANSWER, [question, seen])
            if r["busy"]:
                return ""
            text = fill_frames(log, r["text"], r.get("frames") or [])
            return re.sub(r"\n{3,}", "\n\n", text).strip()
        except Exception:
            pass
    now = panel_text(box)
    new = now[len(before):] if now.startswith(before) else now
    if question in new:
        new = new.split(question, 1)[1]
    return new.strip()


def panel_text(box):
    """Text of the Console AI panel the text box sits in."""
    return box.evaluate("""e => {
        const p = e.closest('[role=dialog],[role=complementary],aside,[class*="assistant" i],[class*="chat" i],[class*="panel" i]');
        let n = p || e; if (!p) for (let i = 0; i < 8 && n.parentElement; i++) n = n.parentElement;
        return n.innerText || '' }""")


def wait_until_signed_in(page, debug, minutes=5):
    """If the console shows its sign-in page, let the person sign in in the window, then carry on."""
    page.wait_for_timeout(2000)
    if not on_signin_page(page):
        return True
    print("Sign in in the browser window (including MFA). This continues by itself once the console has loaded.")
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        page.wait_for_timeout(1500)
        if not on_signin_page(page):
            try:
                page.wait_for_load_state("networkidle", timeout=20000)
            except PWTimeout:
                pass
            page.wait_for_timeout(2000)
            debug.snap(page, "signed_in")
            return True
    print(f"Still on the sign-in page after {minutes} minutes; giving up.")
    return False


def open_console_ai(page, debug):
    box = find_question_box(page)
    if box is None:
        btn = find_ai_button(page)
        if btn is None:
            debug.snap(page, "no_ai_button")
            print("Couldn't find the Console AI button. Is Console AI available in this tenancy and region? "
                  "Run again with --debug and send the debug folder to fix the selectors.")
            return None
        btn.click()
        for _ in range(30):
            page.wait_for_timeout(500)
            box = find_question_box(page)
            if box:
                break
    debug.snap(page, "panel_open")
    if box is None:
        print("Opened Console AI but couldn't find its question box. Run with --debug and send the debug folder.")
    return box


def ask_in_page(page, question, timeout, settle, debug):
    """Type one question into Console AI and return its answer once it stops changing ('' if none)."""
    box = open_console_ai(page, debug)
    if box is None:
        return None
    question = question.strip()
    before = panel_text(box)
    log = console_ai_log(page)
    try:
        seen = log.evaluate(COUNT_QUESTION, question) if log is not None else 0
    except Exception:
        seen = 0
    box.click()
    if box.evaluate("e => e.tagName === 'TEXTAREA' || e.tagName === 'INPUT'"):
        box.fill(question)
    else:
        box.type(question)
    page.keyboard.press("Enter")
    answer, last, stable_since, start = "", None, None, time.time()
    while time.time() - start < timeout:
        page.wait_for_timeout(1000)
        try:
            new = read_answer(page, box, question, before, seen)
        except Exception:
            box = find_question_box(page) or box
            continue
        if new and new == last and not BUSY_WORDS.search(new[-200:]):
            if stable_since and time.time() - stable_since >= settle:
                answer = new
                break
            stable_since = stable_since or time.time()
        else:
            stable_since = None
        last = new
    debug.snap(page, "answer")
    return answer or (last or "")
