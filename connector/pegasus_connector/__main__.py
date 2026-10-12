"""pegasus-connector: register | run | status

  python -m pegasus_connector register --url https://pegasus.example.com --token <one-time token> \
         --ssh-user opc --ssh-key /home/opc/.ssh/id_rsa
  python -m pegasus_connector run
  python -m pegasus_connector status
"""
import argparse
import sys
from pathlib import Path

from . import __version__, protocol
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
    sub.add_parser("run", help="run the connector (foreground)")
    sub.add_parser("status", help="show this connector's registration and local policy")
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
        print(f"Control plane signing key: {protocol.fingerprint(cfg['signing_key'])}")
        print("Check that this matches the key shown in Pegasus, then start the connector with: run")
        print(f"Config saved to {a.config}")
        return 0
    if not Path(a.config).exists():
        print(f"No configuration at {a.config}. Run 'register' first.", file=sys.stderr)
        return 1
    if a.cmd == "status":
        cfg = load_config(a.config)
        pol = load_policy(Path(a.config).parent / "policy.json")
        print(f"Connector {cfg['connector_id']} for {cfg.get('client_name') or cfg['tenant']}")
        print(f"Control plane {cfg['url']}, signing key {protocol.fingerprint(cfg['signing_key'])}")
        print(f"SSH as {cfg['ssh']['user']} with {cfg['ssh']['key_path']}")
        print(f"Local policy: {pol}")
        return 0
    return Agent(a.config).run_forever()


if __name__ == "__main__":
    sys.exit(main())
