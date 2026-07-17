# ImaniIA sandbox setup runbook — dashboard integration

One linear pass. Do the steps IN ORDER; each ends with a verify command —
do not continue past a failed verify. All commands run **on the sandbox VM**
(192.168.100.10) unless marked HOST (the Windows dashboard machine).

Files referenced below live in this repo under `deploy/` — copy them
to the sandbox VM first (e.g. `scp deploy/* user@192.168.100.10:~/`).

## 0. Prerequisites

- CAPE works end-to-end (`cape.service`, `cape-processor.service` active).
- `virsh domstate cuckoo2` answers (libvirt reachable).
- Python 3 + pip available.

## 1. VM wrapper service

```bash
sudo mkdir -p /opt/vm-wrapper
sudo cp vm_wrapper.py /opt/vm-wrapper/
sudo pip3 install flask

# Token: generate once, never commit anywhere
echo "VM_WRAPPER_TOKEN=$(openssl rand -hex 24)" | sudo tee /etc/vm-wrapper.env
echo "VM_WRAPPER_BIND=192.168.100.10" | sudo tee -a /etc/vm-wrapper.env
sudo chmod 600 /etc/vm-wrapper.env

# Scoped sudo (validate BEFORE installing)
sudo visudo -cf vm-wrapper-sudoers && sudo cp vm-wrapper-sudoers /etc/sudoers.d/vm-wrapper
sudo chmod 440 /etc/sudoers.d/vm-wrapper

sudo cp vm-wrapper.service /etc/systemd/system/
# If CAPE does not run as user 'cape', edit User= in the unit AND the
# username in /etc/sudoers.d/vm-wrapper to match.
sudo systemctl daemon-reload && sudo systemctl enable --now vm-wrapper
```

**Verify:**

```bash
TOKEN=$(grep VM_WRAPPER_TOKEN /etc/vm-wrapper.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://192.168.100.10:8090/vm/status
# expected: {"cuckoo2":"shut off"}   (or "running" if a job is live)
curl -s http://192.168.100.10:8090/vm/status
# expected: {"error":"unauthorized"} — no token, no answer
```

## 2. Fix the cuckoo2 VNC port

CAPE reverts/boots cuckoo2 constantly; with `autoport='yes'` the VNC port can
move between boots and websockify would point at nothing.

```bash
sudo virsh edit cuckoo2
# find:  <graphics type='vnc' port='-1' autoport='yes' ...>
# make:  <graphics type='vnc' port='5900' autoport='no' listen='127.0.0.1'>
```

**Verify (must survive a domain restart):**

```bash
sudo virsh vncdisplay cuckoo2      # expected: 127.0.0.1:0   (i.e. port 5900)
# then let CAPE run one task (or virsh start / virsh destroy cuckoo2) and
# check `virsh vncdisplay cuckoo2` again — it must still be :0
```

## 3. websockify

```bash
sudo pip3 install websockify
# quick foreground test:
websockify 192.168.100.10:6080 127.0.0.1:5900
```

**Verify** (second shell):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.100.10:6080
# expected: 405 — websockify answers but refuses a plain non-upgrade GET
# (or use `wscat -c ws://192.168.100.10:6080` if installed: connects, hangs — OK)
```

Then stop the foreground test (Ctrl-C) and make it a service:

```bash
sudo tee /etc/systemd/system/websockify-cuckoo2.service <<'EOF'
[Unit]
Description=websockify bridge to cuckoo2 VNC (5900 -> 6080)
After=network.target

[Service]
ExecStart=/usr/local/bin/websockify 192.168.100.10:6080 127.0.0.1:5900
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now websockify-cuckoo2
```

**Verify:** `systemctl is-active websockify-cuckoo2` → `active`, then repeat
the curl check above.

## 4. noVNC assets

Nothing to do on the sandbox VM — the dashboard serves its own vendored copy at
`/static/novnc/`.

**Verify (HOST):** browse to `http://<dashboard>/static/novnc/core/rfb.js`
while logged in → JavaScript source loads.

## 5. Dashboard `.env` (HOST) — only after 1–4 all pass

Append to the dashboard's `.env` (never commit):

```env
CAPE_VM_WRAPPER_ENABLED=1
CAPE_VM_WRAPPER_URL=http://192.168.100.10:8090
CAPE_VM_WRAPPER_TOKEN=<the token from /etc/vm-wrapper.env>
WEBSOCKIFY_URL=ws://192.168.100.10:6080
```

Restart the dashboard server (config is read at import).

**Verify end-to-end:**

1. Queue a detonation (or re-queue a test row:
   `UPDATE pending_detonation SET status='queued', result=NULL WHERE id=<n>;`)
   and trigger the drained window.
2. Email detail page: panel shows *queued* → *running* with a live screen →
   *done* with the embedded CAPE report.
3. With nothing running, "Open sandbox" shows **No active session right now**
   immediately (no spinner).
4. Kill `websockify` mid-run: the live pane shows "Sandbox view unavailable";
   the verdict/escalation still lands (display-only, fail-safe intact).
