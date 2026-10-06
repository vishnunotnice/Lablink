# Architecture

The CLI owns privileged local administration. `serve` exposes only HTTPS registration and approval polling; it cannot approve requests or run lab commands remotely.

Nodes generate WireGuard keys locally and submit public keys. The hub stores request state and assigns addresses under serialized SQLite transactions. Enrollment tokens and poll credentials are hashed. Invitations are consumed in the same transaction that creates the request. Approval and revocation regenerate the persistent hub config; `--apply` additionally synchronizes the live interface.

Docker labs are independent of the WireGuard enrollment pool. JSON/YAML topology validation creates Compose internal bridge networks and one zone per container. nftables policy is scoped to the lab subnet and a dedicated table; it does not flush unrelated firewall rules. Docker's own isolation still applies.

Snapshots produce committed Docker images only after mount inspection. Reset validates all referenced images before recreating containers. Capture identifies a Docker bridge or accepts an explicit interface and invokes tcpdump without a shell.

SQLite is authoritative for hub state and event history. JSONL audit export and generated configs are replaceable derived artifacts. Events and state have no cryptographic tamper-proof guarantee. Private keys appear in private on-disk configuration but never in audit events.
