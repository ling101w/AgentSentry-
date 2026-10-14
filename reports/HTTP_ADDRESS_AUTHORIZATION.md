# HTTP address authorization

`policy.allowlistedApiHosts` restricts the hostnames accepted by dashboard business HTTP tools. It does not authorize private addresses.

Internal services additionally require `policy.allowedPrivateCidrs`, for example `10.20.0.0/16` or `fd12::/48`. IPv4 RFC1918/CGNAT and IPv6 ULA addresses must match an explicit CIDR. Metadata, link-local, unspecified, multicast and other reserved ranges remain blocked even when a CIDR includes them.

Loopback requires a separate exact scheme/host/port entry in `policy.allowedLoopbackOrigins`. The command lab explicitly grants its initial localhost fixture origin; redirects to another port need their own authorization. This exception is confined to the lab's local target predicate and does not authorize link-local addresses.

GET validates the hostname and every resolved address again on every redirect, then pins the connection to the validated address. POST does not follow redirects. Dashboard notification webhooks use neither private nor loopback exceptions.

These settings govern this HTTP helper, not arbitrary network tools owned by OpenClaw. Host allowlists are hostname-based and do not imply an origin-level restriction on public ports.
