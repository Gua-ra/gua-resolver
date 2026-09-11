Architecture decision records for Gua. The entry point is [ADM-001](ADM-001-identifier-binding-placement-trust.md), the frozen decision set for identifier binding, account placement, resolver trust and federation governance. It is normative. Its locked decisions are reopened by concrete evidence, such as a counterexample, a changed requirement or implementation results, not by preference.
The memos that produced it are preserved under [rationale/](rationale/) with only punctuation normalized. They are the reasoning record. They are not normative.

## Accepted follow-up records

- [ADM-007](ADM-007-canonical-encoding-and-member-entries.md): the `gua-lp.v1` canonical encoding and self-signed member roster entries. Closes the part of O2 that Phase 1 needs; nothing locked in ADM-001 is reopened.

## Implementation status

Which ADM-001 decisions the code on `main` has reached. Everything not listed is still target.

- L1b: implemented (`POST /directory/entries` removed), 2026-09-11. Existing directory rows stay until placement records replace them.
- L1a: implemented in identity-service (the non-interactive `phone_number` + `otp_code` branch of `GET /oauth2/authorize` removed; an authorization code is only issued by the interactive login flow), 2026-09-11.
- L16: interim controls, 2026-09-11. `POST /resolve` is rate-limited per client and globally inside the service (README, "Interim abuse controls") and per source at the ingress (gua-deploy `k8s/services/login-ingress.sh`). It still answers `exists` for any raw E.164 with no account session; the L16 [CODE] sentence predates these controls and is left as written.
