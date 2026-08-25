# Egret

Outbound network monitoring and policy control for Linux — *egress, watched*.

Egret shows which process on your machine is talking to the network, what that
process actually is, and lets you allow or deny it. It is a FastAPI backend with
two front ends: a React web UI and a compiled C++/Qt6 desktop client with a tray
icon and always-on-top approval prompts.

## Status

Working today:

* **Process-attributed capture.** Enumerates every established socket from
  `/proc` and names the owning process, falling back to the owning account when
  a process belongs to another user.
* **Provenance.** Each executable is checked against the package database and
  hashed, so an unpackaged binary reaching the network is visible as such.
* **Policy engine.** Ordered rule matching over process, domain suffix, address,
  port, protocol, and network zone, with specificity scoring and TTL expiry.
* **Reverse DNS.** PTR lookups so rules can be written against a domain rather
  than a rotating CDN address.
* **Web UI and Qt client**, both driven entirely by the REST API.

Not working yet — see [ARCHITECTURE.md](ARCHITECTURE.md):

* **Enforcement does not block.** Rule verdicts are recorded and previewed, but
  native execution is off by default and the packet path is not wired up. Egret
  currently observes; it does not yet stop traffic.
* **Antivirus, ransomware, and behaviour detection are scaffolding.** The
  scoring functions exist and are tested, but nothing feeds them: there is no
  filesystem watcher, and signature content is a placeholder pack.
* **Root-owned processes cannot be named** unless the backend runs privileged,
  because `/proc/<pid>/fd` is restricted.

## Roadmap

Ordered by what unblocks the most. The test suite (99 tests) passes today, so
each item below is about reach, not repair.

### 1. Make enforcement actually enforce

The rule engine already decides; nothing carries the decision to the kernel.

- [ ] Create the `inet egret` table and `outbound` chain on start, instead of
      assuming they exist — `build_linux_commands` emits `nft add rule inet egret
      outbound …` against a chain nothing ever creates.
- [ ] Execute compiled commands when `EGRET_ENABLE_NATIVE_EXECUTION=1`, with a
      dry-run diff first and a rollback path if a batch fails halfway.
- [ ] Reconcile at boot: read the live ruleset, drop rules Egret no longer owns,
      re-apply the ones it does. `reconciliation.py` has the shape, not the wiring.
- [ ] Widen rule compilation past `ip daddr` + `tcp dport`: IPv6 (`ip6 daddr`),
      UDP, and port ranges are all silently dropped from a rule today.

### 2. Per-process blocking

The hard one, and the reason Egret observes rather than blocks. nftables cannot
match a pid, so a rule that says "deny curl" has nothing to compile to.

- [ ] Pick the mechanism: cgroup v2 match, `SO_MARK` via a socket LSM, NFQUEUE
      with a userspace verdict, or eBPF. Each trades latency against how much
      privilege the daemon needs.
- [ ] Write the decision up in ARCHITECTURE.md before implementing it — this
      choice sets the privilege model for everything after it.

### 3. Name root-owned processes

`/proc/<pid>/fd` is unreadable for other users' processes, so connections owned
by root currently show an account instead of a binary.

- [ ] Split a small privileged helper out of the backend, or ship a systemd unit
      with `CAP_SYS_PTRACE` / `CAP_DAC_READ_SEARCH`, so attribution works without
      running the whole API as root.

### 4. Feed the detection services

Antivirus, behaviour and ransomware scoring are implemented and tested, but no
event ever reaches them: there is no filesystem watcher in the tree, and the
signature pack holds one entry, EICAR.

- [ ] An inotify watcher feeding `file_event`, with the usual debounce and
      recursion limits.
- [ ] A real signature pack plus an update path — `updates` endpoints exist and
      have nothing to serve.
- [ ] Canary placement for the ransomware signals, which currently wait on files
      nobody creates.

### 5. Ship it

- [ ] Choose a licence. There is none, so nobody may legally use this yet.
- [ ] Real release signing: `sign_file_stub` is a SHA-256 attestation, or an HMAC
      when a key is set. Neither is a signature anyone can verify against a
      public key.
- [ ] A systemd unit and a `.deb`, so the backend survives a reboot without a
      terminal open.

## Quick start

```bash
cd src/avwork
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q

npm install && npm run build          # or: bun install && bun run build
EGRET_DB_PATH=./egret.sqlite3 uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>, or build the desktop client:

```bash
cd egret-qt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build --prefix /usr/local   # adds launcher entry and icon
egret
```

Prompting is opt-in — tick **Ask on new** in the sidebar.

## Layout

| Path | What it is |
| --- | --- |
| `src/avwork/app/` | FastAPI backend: API, services, SQLite storage, telemetry |
| `src/avwork/app/ui/` | React web UI |
| `egret-qt/` | Compiled C++/Qt6 desktop client |
| `littlesnitch-linux/` | Not in this repo — optional upstream clone, see below |

## Configuration

| Variable | Purpose |
| --- | --- |
| `EGRET_DB_PATH` | SQLite database path (defaults to in-memory) |
| `EGRET_INGEST_TOKEN` | Bearer token for the sensor ingest endpoints |
| `EGRET_ENABLE_NATIVE_EXECUTION` | Set to `1` to allow real host firewall changes |
| `EGRET_REVERSE_DNS` | Set to `0` to disable PTR lookups during capture |
| `EGRET_URL` | Backend URL used by the Qt client |

The `EDGE_NET_GUARDIAN_*` spellings are still accepted for older deployments.

## Licence

This project has no licence yet — choose one before distributing.

The Linux packet-path reference is **not** included here. It is GPL-2.0 source
from Objective Development, deliberately kept out of the tree so its licence
does not attach to this project. Clone it alongside if you need it:

```bash
git clone https://github.com/obdev/littlesnitch-linux.git
```

Note that "Little Snitch" is a trademark of Objective Development; this project
is unaffiliated.
