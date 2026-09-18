# Authorizations

The package performs no writes and grants nothing on its own. Every function module runs an `AUTHORITY-CHECK` against the calling user's own SAP authorizations before it reads or runs anything — the RFC service user sees exactly what its PFCG role allows, and no more.

At minimum, the service user needs **S_RFC** to call the function group. Beyond that, it needs the ordinary read authorizations for whatever you want it to extract — the package checks these as the user, it does not escalate or bypass them.

## Authorization objects

| Object | Fields | Purpose |
|---|---|---|
| S_RFC | RFC_TYPE = FUGR, RFC_NAME = Z_PLAIDCL (+ SYST) | Call the RFC-enabled function modules |
| S_TABU_NAM | ACTVT = 03, TABLE = \<tables to read\> | Read specific tables (table reader) |
| S_TABU_DIS | ACTVT = 03, DICBERCLS = \<auth group\> | Fallback table read, scoped by authorization group |
| S_TCODE | TCD = SA38, plus each transaction to run | Run reports and transactions |
| S_PROGRAM | P_GROUP = \<program auth group\>, P_ACTION = SUBMIT | Run programs |
| S_QUERY | ACTVT = 23 | Run SQ01 queries |
| S_DEVELOP | OBJTYPE, OBJNAME, ACTVT = 03 | Read object source where needed |

All values above are display/read (`ACTVT` 03, 16, or 23) — the package performs no writes.

Scope `S_TABU_NAM` and `S_TCODE` to only the specific tables and transactions you intend to extract. The package enforces whatever the role grants, so a tightly scoped role is the effective control on what PlaidCloud can read.
