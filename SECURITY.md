# Security and operational boundaries

Use a disposable test hub and only networks you administer. Run the enrollment API on a private, firewall-restricted network. TLS verification is mandatory; transfer the certificate through a trusted channel. Invitations and enrollment tokens grant registration requests, not automatic approval.

The host administrator can read keys, alter audit records and control containers. Store `/var/lib/lablink` with private permissions and protect backups as secret material. Do not commit state databases, node enrollment files, keys or PCAPs to a public repository.

Use `revoke ID --apply` for immediate live revocation. If synchronization fails, restore host access and run `repair --apply`; a saved revoked record alone does not remove the live peer.

Review overlapping subnets, target images, credentials and nftables output before provisioning. The bundled target password is for isolated exercises only. Do not publish target ports or assume a bridged VM becomes isolated merely by adding WireGuard.

Mounted data is excluded from Docker commit. Snapshot creation refuses mounts instead of silently losing that data. Coordinated application backup and VM provider snapshots remain future work.
