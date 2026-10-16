"""pegasus-connector: register | run | status

  python -m pegasus_connector register --url https://pegasus.example.com --token <one-time token> \
         --ssh-user opc --ssh-key /home/opc/.ssh/id_rsa
  python -m pegasus_connector run
  python -m pegasus_connector status
  python -m pegasus_connector oracle-login --user you@example.com [--jms-token <token>]
"""
import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from . import __version__, oracle, protocol, updater
from .agent import Agent, default_config_dir, load_config, register
from .policy import load as load_policy


def main(argv=None):
    p = argparse.ArgumentParser(prog="pegasus-connector", description="Pegasus connector " + __version__)
    p.add_argument("--config", default=str(default_config_dir() / "config.json"), help="config file path")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register", help="register this connector with a one-time token")
    r.add_argument("--url", required=True, help="control plane URL, e.g. https://pegasus.example.com")
    r.add_argument("--token", required=True, help="one-time registration token from Pegasus")
    r.add_argument("--ssh-user", default="opc", help="account the connector signs in to servers as (default opc)")
    r.add_argument("--ssh-key", required=True, help="path to that account's private key on this machine")
    r.add_argument("--name", help="name shown in Pegasus (default: this machine's host name)")
    rn = sub.add_parser("run", help="run the connector (foreground); runs the newest verified update if one is installed")
    rn.add_argument("--child", action="store_true", help=argparse.SUPPRESS)   # started by the supervisor
    sub.add_parser("status", help="show this connector's registration and local policy")
    o = sub.add_parser("oracle-login", help="save the Oracle Support account this connector downloads patches with")
    o.add_argument("--user", help="Oracle Support (MOS) user name; the password is asked for, or read from "
                                  "PEGASUS_MOS_PASSWORD")
    o.add_argument("--jms-token", help="Java Management Service download token, for OTN-licensed JDK downloads")
    o.add_argument("--forget", action="store_true", help="remove the saved Oracle account and token")
    a = p.parse_args(argv)

    if a.cmd == "register":
        if not Path(a.ssh_key).expanduser().exists():
            print(f"The SSH key {a.ssh_key} doesn't exist on this machine.", file=sys.stderr)
            return 1
        try:
            cfg = register(a.url, a.token, a.config, a.ssh_user, a.ssh_key, a.name)
        except Exception as e:
            print(e, file=sys.stderr)
            return 1
        print(f"Registered for {cfg.get('client_name') or cfg['tenant']} as {cfg['connector_id']}.")
        print(f"This connector created its own key; Pegasus issued certificate {cfg['certificate']['serial']} for it "
              f"(valid until {time.strftime('%Y-%m-%d', time.localtime(cfg['certificate']['not_after']))}, "
              "renewed automatically).")
        print(f"Control plane signing key: {protocol.fingerprint(cfg['signing_key'])}")
        print("Check that this matches the key shown in Pegasus, then start the connector with: run")
        print(f"Config saved to {a.config}")
        return 0
    if not Path(a.config).exists():
        print(f"No configuration at {a.config}. Run 'register' first.", file=sys.stderr)
        return 1
    if a.cmd == "oracle-login":
        return oracle_login(a)
    if a.cmd == "status":
        cfg = load_config(a.config)
        pol = load_policy(Path(a.config).parent / "policy.json")
        print(f"Connector {cfg['connector_id']} for {cfg.get('client_name') or cfg['tenant']}")
        print(f"Control plane {cfg['url']}, signing key {protocol.fingerprint(cfg['signing_key'])}")
        if cfg.get("certificate"):
            c = cfg["certificate"]
            print(f"Certificate {c['serial']}, valid until {time.strftime('%Y-%m-%d', time.localtime(c['not_after']))} "
                  "(renewed automatically)")
        else:
            print("Signs in with a shared secret; it switches to a certificate the next time it starts")
        print(f"SSH as {cfg['ssh']['user']} with {cfg['ssh']['key_path']}")
        print(f"Local policy: {pol}")
        print(f"Code version {__version__}; updates "
              + ("accepted when signed by " + ", ".join(protocol.fingerprint(k) for k in updater.RELEASE_KEYS)
                 if updater.RELEASE_KEYS else "not possible (no release key built in)"))
        for vt, d in updater.installed(a.config):
            print(f"  installed update {d.name}{' (in use)' if vt > protocol.version_tuple(__version__) else ''}")
        sec = oracle.load_secrets(a.config)
        print(f"Oracle Support account: {sec.get('mos_user') or 'not set (run oracle-login)'}"
              f"{'; Java download token set' if sec.get('jms_token') else ''}")
        return 0
    if a.child:
        return Agent(a.config).run_forever()
    return updater.supervise(a.config, lambda: Agent(a.config).run_forever())


def oracle_login(a):
    if a.forget:
        oracle.save_secrets(a.config, {})
        print("Removed the saved Oracle account and token.")
        return 0
    sec = oracle.load_secrets(a.config)
    if a.user:
        pw = os.environ.get("PEGASUS_MOS_PASSWORD") or getpass.getpass(f"Oracle Support password for {a.user}: ")
        try:
            oracle.MOSClient(a.user, pw).login()
        except oracle.MOSError as e:
            print(e, file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Couldn't reach Oracle Support from this machine: {e}", file=sys.stderr)
            return 1
        sec.update(mos_user=a.user, mos_password=pw)
        print(f"Signed in to Oracle Support as {a.user}.")
    if a.jms_token:
        sec["jms_token"] = a.jms_token.strip()
        print("Saved the Java download token.")
    if not a.user and not a.jms_token:
        print("Give --user and/or --jms-token.", file=sys.stderr)
        return 1
    oracle.save_secrets(a.config, sec)
    print(f"Saved to {oracle.secrets_path(a.config)} (readable only by this account). The control plane never "
          "receives it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
