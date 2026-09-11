Architecture decision records for Gua. The entry point is [ADM-001](ADM-001-identifier-binding-placement-trust.md), the frozen decision set for identifier binding, account placement, resolver trust and federation governance. It is normative. Its locked decisions are reopened by concrete evidence, such as a counterexample, a changed requirement or implementation results, not by preference.
The memos that produced it are preserved under [rationale/](rationale/) with only punctuation normalized. They are the reasoning record. They are not normative.

## Implementation status

Which ADM-001 decisions the code on `main` has reached. Everything not listed is still target.

- L1b: implemented (`POST /directory/entries` removed), 2026-09-11. Existing directory rows stay until placement records replace them.
- L1a: in progress in identity-service, in the same change set as L1b.
- L16: interim controls, 2026-09-11. `POST /resolve` is rate-limited per client and globally inside the service (README, "Interim abuse controls") and per source at the ingress (gua-deploy `k8s/services/login-ingress.sh`). It still answers `exists` for any raw E.164 with no account session; the L16 [CODE] sentence predates these controls and is left as written.
