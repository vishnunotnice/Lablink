# LabLink

**A WireGuard lab network with a Python management layer for enrollment, isolated Docker ranges, capture, and recovery.**

Created for **Vishnu Moguluri** · [Website](https://vishnumoguluri.com) · hello@vishnumoguluri.in

This repository is a **new reconstruction from your saved README and confirmed lab setup**, not a recovered copy of the original source. Version 0.2.0 contains implemented workflows and tests; it has not been validated on your actual hub yet.

## Included

- HTTPS enrollment with locally generated WireGuard keys and manual hub approval.
- Hashed enrollment credentials, expiring one-time invitation links, and per-request poll credentials.
- SQLite transactions for concurrent registration and address allocation.
- Persistent hub configuration, explicit live synchronization, revocation records, and audit export.
- Docker Compose templates on internal bridge networks.
- Dedicated nftables policy generation, review, validation, and explicit application.
- Terminal status dashboard, tcpdump capture, optional Wireshark viewing and offline Zeek analysis.
- Container filesystem snapshots and reset, with mounted containers refused.
- Explicit systemd unit generation and opt-in boot enablement.
- `lablink`, `lanlink`, and `homelab` command aliases.
- Your four-node inventory and a standalone TCP health checker.

## Install

On a Linux hub, install Python 3.10+, WireGuard, Docker Engine with Compose v2, nftables, and tcpdump using your distribution's packages. Then:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/lablink --help
```

For privileged operations, use the absolute path to `.venv/bin/lablink`; a virtual environment does not automatically stay on `sudo`'s PATH.

Start with [docs/SETUP.md](docs/SETUP.md). Run the read-only checker against your existing lab without altering WireGuard:

```bash
python3 examples/health_check.py
```

## Commands

Global options must precede the command: `lablink --data-dir /path command`.

| Command | Behavior |
|---|---|
| `init` | Create hub state and a generated tunnel file; does not replace an existing tunnel |
| `serve` | Run the TLS enrollment API |
| `join --wait` | Request approval and save a node tunnel after approval |
| `status`, `nodes` | Show enrollment records; this is not live heartbeat status |
| `approve ID --apply` | Approve a node, rebuild persistent config, synchronize the active hub |
| `revoke ID --apply` | Revoke a node, rebuild config, remove it from the active hub |
| `invite --expires 2h` | Create a one-use enrollment URI |
| `repair --apply` | Regenerate config and synchronize an already active interface |
| `up --template ad-pentest` | Create and start the Docker training range |
| `up --topology PATH` | Validate and start a custom range |
| `policy --lab NAME` | Print the scoped nftables policy for review |
| `policy --lab NAME --apply` | Validate and apply the dedicated table |
| `down --lab NAME` | Remove containers and networks; snapshot images and policy remain |
| `dashboard --lab NAME --watch` | Repeated Compose status display |
| `capture ZONE --lab NAME --output PATH` | Capture until Ctrl+C; optional `--interface`, `--zeek`, `--wireshark` |
| `snapshot --lab NAME --name clean` | Commit unmounted container filesystems |
| `reset --lab NAME --snapshot clean` | Recreate containers from committed images |
| `check` | Check tools, private file modes, and active WireGuard interface |
| `protect --hub --lab NAME` | Generate units for review |
| `protect --hub --lab NAME --enable` | Install units and enable them for boot |
| `audit` | Export and display administration events |

Without `--apply`, approval/revocation changes saved state only. A revoked peer may still communicate until the active interface is synchronized. Use `--apply` for live changes; failures are reported and `repair --apply` retries reconciliation.

## Your existing lab

| Node | Role | Overlay IP | Expected service |
|---|---|---|---|
| Ubuntu | Hub | 10.1.2.11 | SSH 22 |
| Windows | Server | 10.1.2.10 | RDP 3389 |
| Fedora | Server | 10.1.2.12 | SSH 22 |
| Kali | Attacker | 10.1.2.13 | SSH 22 |

Hub LAN address recorded in your setup: `192.168.1.26`. New automatic enrollments allocate free addresses and **do not import these existing peers or guarantee these exact IPs**. Do not replace your current `wg0` with this generated configuration without migrating all peers. A WireGuard overlay alone does not isolate bridged VMs from their home LAN.

## Limits that matter

- `ad-pentest` is OpenLDAP + DVWA + Kali + an idle Zeek container; it is not Microsoft Active Directory. Kali ships without a preinstalled pentesting toolset. Zeek is available for offline PCAP analysis; the monitoring container is not an automatic network sensor.
- Docker internal networks provide isolation. Generated accept rules do not override Docker's bridge isolation or create routing between zones. Cross-zone access needs a deliberately configured router or separate provider implementation; this version does not provision one.
- Some images, especially directory/database images, declare volumes. Snapshots refuse those containers. They do not back up volumes, RAM, running application transactions, host configuration, or an entire VM. Per-container pause does not make a multi-container snapshot transactionally consistent.
- `check` does not implement node heartbeats, automated diagnosis, or service probes; the standalone inventory checker provides TCP probes.
- systemd units enable boot startup only. Review paths, policy and the environment before enabling. They do not configure IP forwarding, remote router port forwarding, or internet reachability.
- The enrollment API is a small TLS server for a trusted private lab. It has request size/time limits but no production rate limiter, multi-user RBAC, or internet-facing hardening.
- Audit events are application-managed SQLite rows, exported as JSONL. They are not tamper-proof against the local administrator. Failed external operations are not recorded as successful actions.
- No hypervisor provider, VM snapshot hooks, invitation delivery service, full-screen TUI, or configuration export exists in this reconstruction. See [docs/ROADMAP.md](docs/ROADMAP.md).
- Image tags reflect the saved design and need verification on your host. Pin reviewed image digests for reproducible deployments.

## Development

Tests cover credentials, one-time invitations under concurrency, approval, revocation, address allocation, audit redaction, policy scoping, topology validation, file permissions, and mounted-container refusal. Docker, WireGuard, nftables, systemd, capture, and image pull compatibility require live integration testing.

See [docs/VALIDATION.md](docs/VALIDATION.md) for the recorded checks. No third-party repository source was copied into this reconstruction. No open-source license is assigned: select a license before publishing it as an open-source tool.
