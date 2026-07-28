"""Port-exposure hardening guards.

Keeps the app's listening surface locked down so a future edit can't silently
re-expose a service on all network interfaces:
  1. The dashboard binds loopback by default (not 0.0.0.0).
  2. No docker-compose published port listens on all interfaces — every
     host-published port is pinned to 127.0.0.1.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_dashboard_default_host_is_loopback():
    src = (REPO_ROOT / "src" / "main.py").read_text(encoding="utf-8")
    m = re.search(r'os\.getenv\(\s*["\']DASHBOARD_HOST["\']\s*,\s*["\']([^"\']+)["\']\s*\)', src)
    assert m, "DASHBOARD_HOST default not found in main.py"
    assert m.group(1) == "127.0.0.1", (
        f"DASHBOARD_HOST defaults to {m.group(1)!r} — must be 127.0.0.1 so the "
        "dashboard isn't exposed on all interfaces over plain HTTP."
    )


def test_compose_publishes_only_to_loopback():
    compose = REPO_ROOT / "docker-compose.yml"
    if not compose.exists():
        return
    offenders = []
    # A YAML port publish looks like:  - "HOST:CONTAINER"  or  - "IP:HOST:CONTAINER"
    publish_re = re.compile(r'^\s*-\s*["\']?([^"\'\n]+)["\']?\s*$')
    port_map_re = re.compile(r'^(?:(?P<ip>[\d.]+):)?(?P<hostport>\d+):(?P<containerport>\d+)$')
    for line in compose.read_text(encoding="utf-8").splitlines():
        m = publish_re.match(line)
        if not m:
            continue
        pm = port_map_re.match(m.group(1).strip())
        if not pm:
            continue  # not a port mapping (e.g. a volume, env, or depends_on)
        ip = pm.group("ip")
        if ip != "127.0.0.1":
            offenders.append(m.group(1).strip())
    assert not offenders, (
        f"docker-compose publishes ports on all interfaces: {offenders} — "
        "prefix each with 127.0.0.1: (loopback) so nothing binds 0.0.0.0."
    )
