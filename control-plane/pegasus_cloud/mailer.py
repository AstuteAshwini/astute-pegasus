"""Outgoing email (SMTP): sign-in links for new people and password resets.

Works with any SMTP relay, for example Google Workspace (smtp-relay.gmail.com or smtp.gmail.com with an app password)
or OCI Email Delivery (smtp.email.<region>.oci.oraclecloud.com, port 587, with SMTP credentials). The password is
stored encrypted by the caller.
"""
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

DEFAULTS = {"enabled": False, "host": "", "port": 587, "security": "starttls", "user": "", "from_email": "",
            "from_name": "Pegasus"}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class MailError(Exception):
    pass


def config(stored):
    c = dict(DEFAULTS)
    c.update(stored or {})
    return c


def validate(body, c, has_password):
    problems = []
    host = str(body.get("host", c["host"]) or "").strip()
    if host and not re.fullmatch(r"[A-Za-z0-9.\-]{1,200}", host):
        problems.append("The SMTP server should be a host name like smtp.email.us-phoenix-1.oci.oraclecloud.com.")
    try:
        port = int(body.get("port", c["port"]) or 0)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        problems.append("The port is a number, usually 587 (STARTTLS) or 465 (SSL).")
    security = body.get("security", c["security"])
    if security not in ("starttls", "ssl", "none"):
        problems.append("Choose STARTTLS, SSL or none.")
    sender = str(body.get("from_email", c["from_email"]) or "").strip()
    if sender and not EMAIL.match(sender):
        problems.append("The From address isn't an email address.")
    enabled = bool(body.get("enabled", c["enabled"]))
    new = {"enabled": enabled, "host": host, "port": port, "security": security,
           "user": str(body.get("user", c["user"]) or "").strip()[:200], "from_email": sender,
           "from_name": str(body.get("from_name", c["from_name"]) or "").strip()[:80] or "Pegasus"}
    if enabled and not (host and sender):
        problems.append("Fill in the SMTP server and the From address before switching email on.")
    if enabled and new["user"] and not has_password:
        problems.append("Add the SMTP password before switching email on.")
    return new, problems


def send(cfg, password, to, subject, text, html=None, timeout=20):
    """Send one message. Raises MailError with a readable reason."""
    if not cfg.get("host") or not cfg.get("from_email"):
        raise MailError("Email isn't set up yet.")
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.get("from_name") or "Pegasus", cfg["from_email"]))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=cfg["from_email"].split("@", 1)[1])
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    try:
        if cfg["security"] == "ssl":
            s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=timeout, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=timeout)
        with s:
            if cfg["security"] == "starttls":
                s.starttls(context=ssl.create_default_context())
            if cfg.get("user"):
                s.login(cfg["user"], password or "")
            s.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise MailError("The SMTP server refused the user name or password.")
    except smtplib.SMTPRecipientsRefused:
        raise MailError(f"The SMTP server refused to send to {to}.")
    except smtplib.SMTPSenderRefused:
        raise MailError(f"The SMTP server won't send from {cfg['from_email']}. Use an address it's allowed to send as.")
    except (smtplib.SMTPException, OSError) as e:
        raise MailError(f"Couldn't send email through {cfg['host']}:{cfg['port']}: {e}")
