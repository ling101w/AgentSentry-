# Security Policy

## Supported Version

Security fixes target the latest `0.2.x` source on `main`.

## Reporting

Do not open a public issue for a vulnerability that could expose credentials, bypass a deterministic deny, poison persistent memory, or execute an unapproved tool. Contact the repository owner privately through the security-reporting channel configured on the Git hosting account. Include the affected commit, minimal reproduction, expected boundary, actual decision, and any redacted audit record IDs.

Never include live API keys, tokens, private keys, user messages, or production tool results. Replace them with synthetic fixtures and keep proof-of-concept targets local or explicitly authorized.

## Scope

High-priority issues include:

- deterministic `deny` downgraded by semantic or operator-cache logic;
- side effects released without explicit TaskSpec authority;
- memory or tool output granting new authority;
- tainted/secret fields reaching an external sink without evidence;
- Tool Manifest integrity bypass;
- approval-cache collisions across parameters or policy versions;
- secret leakage in JSONL records, exports, notifications, or Dashboard views.
