# Setup on an isolated Linux test hub

Use a new VM first. This code does not automatically migrate your existing four-node lab. Run `.venv/bin/lablink --help` and each command's `--help` for options.

## 1. Create a certificate

Replace the address with your test hub's address. The SAN must match the HTTPS address. Transfer the public certificate to nodes over a trusted channel.

```bash
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout hub.key -out hub.crt \
  -subj '/CN=192.168.1.26' \
  -addext 'subjectAltName=IP:192.168.1.26'
chmod 600 hub.key
```

## 2. Initialize

From the extracted repository directory:

```bash
sudo "$PWD/.venv/bin/lablink" init \
  --subnet 10.1.2.0/24 --hub-ip 10.1.2.11 \
  --endpoint 192.168.1.26:51820 \
  --registration-url https://192.168.1.26:8787 \
  --tls-cert "$PWD/hub.crt" --tls-key "$PWD/hub.key"
```

Save the printed enrollment token securely. This creates a private state database and `/var/lib/lablink/wg0.conf`. It does not install or start the tunnel.

On a **new hub without an existing wg0 configuration**:

```bash
sudo install -m 600 /var/lib/lablink/wg0.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
sudo sysctl -w net.ipv4.ip_forward=1
sudo "$PWD/.venv/bin/lablink" serve
```

To preserve forwarding across reboot on this dedicated hub, add `net.ipv4.ip_forward=1` to a reviewed file in `/etc/sysctl.d/`. Allow the intended peer-to-peer forwarding in the hub firewall. This project does not replace or flush your firewall automatically. UDP 51820 and TCP 8787 must be reachable from participating nodes. LAN endpoints are not remotely reachable through the internet without a separate reachable endpoint and router setup.

## 3. Enroll and approve

On a Linux node with WireGuard tools and this package installed:

```bash
sudo "$PWD/.venv/bin/lablink" join \
  --hub-url https://192.168.1.26:8787 \
  --ca-cert ./hub.crt --name kali-new --wait
```

Enter the enrollment token at the hidden prompt. On the hub, in another terminal:

```bash
sudo "$PWD/.venv/bin/lablink" status
sudo "$PWD/.venv/bin/lablink" approve REQUEST_ID --apply
```

The node saves `/var/lib/lablink/wg0.conf`. Install it and start the node tunnel explicitly, as on the hub. Keep the certificate check enabled. For a Windows node, `wg.exe` must be on PATH; use a writable `--data-dir` before `join`, then import the resulting tunnel into WireGuard for Windows. Windows behavior has not been integration-tested here.

`join --fresh` discards local pending enrollment state and generates another key. Existing names remain reserved, including revoked names; use a new name.

## 4. Templates, capture, snapshots

```bash
sudo "$PWD/.venv/bin/lablink" up --template ad-pentest
sudo "$PWD/.venv/bin/lablink" dashboard --lab ad-pentest
sudo "$PWD/.venv/bin/lablink" policy --lab ad-pentest
sudo "$PWD/.venv/bin/lablink" policy --lab ad-pentest --apply
sudo "$PWD/.venv/bin/lablink" capture targets --lab ad-pentest --output ./targets.pcap
```

Press Ctrl+C to stop capture. Optional Zeek analysis runs on the host and requires the host `zeek` binary. Prefer a non-root Wireshark session to view the PCAP after capture.

Review subnet overlap with your LAN, VPNs, and existing Docker networks before launch. Internal networks do not publish target services on the host. Access a same-zone container through `docker compose exec` with the saved Compose file. Cross-zone routing is not configured automatically.

For a custom topology whose container images have **no mounts**:

```bash
sudo "$PWD/.venv/bin/lablink" snapshot --lab NAME --name baseline
sudo "$PWD/.venv/bin/lablink" reset --lab NAME --snapshot baseline
```

The supplied OpenLDAP/DVWA template may fail snapshot validation because the images declare volumes. This is an intentional refusal to produce an incomplete backup.

## 5. Boot services

Keep the Python environment at a stable absolute path. Generate units first:

```bash
sudo "$PWD/.venv/bin/lablink" protect --hub --lab ad-pentest
```

Review the files under `/var/lib/lablink/units/`, then install and enable them:

```bash
sudo "$PWD/.venv/bin/lablink" protect --hub --lab ad-pentest --enable
```

Enablement affects the next boot; it does not start all services immediately. `wg-quick` needs the installed `/etc/wireguard/wg0.conf`. Verify boot behavior in a test VM before using it for your main lab.

## Reconciliation and recovery

If a live approval/revocation application fails, records remain persisted, and the CLI returns an error. Run `repair --apply` once the hub interface is active to synchronize it. `down` does not delete a previously applied nftables table; remove only the named `lablink_NAME` table after review if retiring that lab. Snapshot images remain until explicitly removed using Docker. Never run a host-wide Docker or firewall cleanup as part of ordinary lab reset.
