"""Run a connector against simulated PeopleSoft servers, for demos and UI work without real servers.

  python scripts/demo_servers.py --config /path/to/connector/config.json
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "connector"), str(ROOT / "tests")]

from pegasus_connector.agent import Agent  # noqa: E402
from fakes import FakeServers  # noqa: E402


class SlowFake(FakeServers):
    def run(self, *a, **kw):
        time.sleep(0.6)          # feels like real psadmin
        return super().run(*a, **kw)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    a = p.parse_args()
    sys.exit(Agent(a.config, runner=SlowFake()).run_forever())
