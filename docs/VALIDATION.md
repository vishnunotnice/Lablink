# Validation record

Date: 2026-10-03. Runtime: Python 3.12 in the reconstruction workspace.

- **24 tests passed**, including a real local HTTPS enrollment/approval/revocation round trip and rejection of an untrusted TLS certificate.
- Concurrent invitation reuse: exactly one enrollment succeeds.
- Concurrent normal enrollments allocate distinct addresses and reserve the hub address.
- Revoked keys cannot re-enroll or be reapproved.
- Audit output excludes enrollment/poll tokens and private key material.
- Internal Compose network generation, scoped nftables policy output, topology input validation, private file writes and mounted-container snapshot refusal pass.
- Python bytecode compilation passes.
- Wheel build passes; install into a separate virtual environment passes.
- Installed `lablink`, `lanlink` and `homelab` CLI help commands work.

Not executed: real WireGuard interface synchronization; Docker image pulls and startup; nftables kernel application; Docker snapshot/restore; tcpdump/Zeek/Wireshark; systemd reboot; Windows enrollment. The tests do not prove those integrations work on the user's machine. This archive does not change any existing lab node.
