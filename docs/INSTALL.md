# Install Guide

This package installs as a single ABAP package, `ZPLAIDCL`, containing one function group, `Z_PLAIDCL`. Since it lives in your own Z-namespace, no SAP namespace registration or developer key is required.

## Prerequisites

- **abapGit** installed on the target system. If it isn't already, follow the standard standalone-report install at [docs.abapgit.org](https://docs.abapgit.org/).
- A target package name of **`ZPLAIDCL`**. abapGit will create it if it doesn't exist.

## Path A — Offline ZIP (recommended for production)

Use this path when the SAP system has no outbound internet access, which is typical for production.

1. Download the release ZIP for the version you want to install.
2. In abapGit, choose **New Offline**.
3. Import the ZIP, targeting package **`ZPLAIDCL`**.
4. Run **Pull**, then mass-activate the imported objects.

abapGit activates objects in dependency order automatically — no manual sequencing needed.

## Path B — Online Clone (sandbox/dev with Git egress)

Use this path on systems that can reach external Git over HTTPS.

1. In abapGit, choose **New Online**.
2. Enter this repository's URL as the source.
3. Set the target package to **`ZPLAIDCL`**.
4. Run **Pull**, then activate.

HTTPS access requires the repository's certificate to be trusted in **STRUST**. Import it there first if the clone fails on a TLS handshake.

## Post-Install Verification

1. Go to **SE37**.
2. Enter function module **`Z_PLAIDCL_B1_CAPABILITIES`** and choose **Execute**.
3. Confirm `EV_PACKAGE_VERSION = 1.0.0`.
4. Confirm the returned capability probes (RFC_READ_TABLE reachable, SQ01 catalog reachable, SALV headless, DDIC readable) all come back green, along with `EV_SYSID`, `EV_SAPRELEASE`, and `EV_KERNEL_RELEASE`.

## Create the RFC Service User

Create (or designate) a background RFC/communication user for PlaidCloud to connect as, and assign it a PFCG role scoped to the tables, queries, and transactions you intend to extract. See [authorizations.md](authorizations.md) for the exact authorization objects to include.

## Update

To move to a newer release: pull the newer version in abapGit (online) or import the newer release ZIP (offline), then re-activate. Existing objects update in place.

## Uninstall

Delete package **`ZPLAIDCL`** — this removes the function group and every object in it. Then remove the PFCG role from the service user.
