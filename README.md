# PlaidCloud SAP Extraction Package

A single ABAP package (`ZPLAIDCL`) that lets PlaidCloud read data from your SAP system: tables, SQ01 queries, transactions and reports, selection screens, and variants. It is read-only — every function module streams data out; none of them write to your system. Requires only SAP_BASIS (NetWeaver ABAP), so it installs the same way on ECC and S/4HANA with no S4CORE or ERP add-ons.

## Requirements

- SAP_BASIS / NetWeaver ABAP — ECC or S/4HANA.
- A background RFC/communication user for PlaidCloud to connect as, with a PFCG role scoped to what you want extracted (see [docs/authorizations.md](docs/authorizations.md)).

## Install

See [docs/INSTALL.md](docs/INSTALL.md) for full steps. In short: use abapGit to bring the package into `ZPLAIDCL` — either an **offline ZIP** import (recommended for production systems with no internet access) or an **online clone** from this repo (for sandbox/dev systems with Git egress).

## Verify

After activation, run `Z_PLAIDCL_B1_CAPABILITIES` in SE37. It returns the installed package version and a healthcheck of the environment. Confirm `EV_PACKAGE_VERSION = 1.0.0` and that the capability probes come back green.

## Authorizations

The package performs no writes and grants nothing beyond what you assign. Every read or run is gated by a standard `AUTHORITY-CHECK` against the calling user's own SAP authorizations — the service user sees exactly what its role allows, nothing more. See [docs/authorizations.md](docs/authorizations.md) to scope the PFCG role.

## License

Apache 2.0 — see [LICENSE](LICENSE).
