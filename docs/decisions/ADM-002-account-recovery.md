# ADM-002: Account recovery

> **Status: Proposed, not frozen.** It closes when independent distributed-systems and cryptography reviewers answer Q1 to Q7, and spikes SR1 and SR2 pass.

## Context

ADM-001 L4 commits the initial authority key and recovery framework in `AccountGenesis`, and delegates recovery-policy transitions here. L7 makes identifier-channel compromise irreducible. L13 locks four requirements and defers the mechanism to O5 and O6, leaving O9 and O11 open.

ADM-008 fixes the genesis bytes. Its framework `0x01` commits one 32-byte recovery authority key, with no field for a threshold or delay bound.

Product facts, `[CODE]` identity-service `main` at `e21fd78`:

- `/security/pin/reset` and `/security/pin/reset/complete` are unauthenticated. An SMS OTP, 7 days of account inactivity, then a 7-day wait, replaces the PIN, unnotified and unopposable (issue #31).

## Scope

In scope: authority-key recovery, login-factor recovery, the SMS PIN reset, and the first shippable step.

Out of scope: E2EE message-key recovery except R9, whole-homeserver failure, governance-key loss (O13), relying-party architecture (O11).

## Requirements

- R1. Authority recovery is initiated only by a genesis-committed threshold. (L13.1)
- R2. Rotation and recovery conflicts resolve deterministically, not by signing speed. (L13.2)
- R3. Veto authority is precommitted, never the active key alone. (L13.3)
- R4. Loss of every committed factor may be final. (L13.4)
- R5. Identifier possession never authorizes an authority transition. (L2, L3, L7)
- R6. A stronger factor closes weaker reset paths. (issue #31)
- R7. Every factor reset notifies all sessions and devices, and allows opposition. (identity-service PR #16, issue #31)
- R8. Every delay on an authority or binding transition runs on sequenced time witnesses can replay. (L11) A homeserver-local reset is neither, so its delays run on service time.
- R9. A secret protecting key material resists offline guessing, and a 6-digit PIN does not. (key-recovery decision, 2026-08-28; gua-ios #58, gua-android #23)

## Options considered

Authority key recovery:

- A1, operator or homeserver escrow, fails R4 and R5: operator action plus a SIM swap is takeover from nothing.
- A2, identifier OTP plus delay, fails R5, turning L7's residual into durable takeover.
- A3, genesis-committed factors with delay, precommitted veto and rank-ordered conflicts. It is intended to satisfy R1 to R5 and R8, pending SR1 and Q1 to Q3. Delay with clawback by a separately held key is the vault pattern [Möser, Eyal, Sirer, "Bitcoin Covenants", FC 2016 Workshops].
- The PIN fails R9. Only a guess-limited hardware vault could use it [Dauterman, Corrigan-Gibbs, Mazières, "SafetyPin", OSDI 2020], and the 2026-08-28 note recommends against one.

PIN reset:

- P1, keeping the current path, fails R6 and R7. P2, deleting it, strands PIN-only accounts.
- P3, SMS plus delay plus opposition, device-bound, for accounts without a stronger factor. It satisfies R6 and R7. L7's residual stays unmitigated, and the delay constrains only this path.
- P4, SMS plus a long delay, moving the identifier to a new account by L3 supersession. The old account does not transfer. It changes a federation binding, so it runs through L6, L8 and L11's sequenced time.

SIM swaps are routinely achievable [Lee, Kaiser, Mayer, Narayanan, SOUPS 2020]. NIST SP 800-63B classes SMS OTP as a restricted authenticator.

## Decision or narrowed choice

D1. Authority recovery uses A3, as recovery framework `0x02`. Its genesis fields commit the framework id, a factor-key-set commitment, `t`, and bounds on `Δr` and `Δp`. Every committed factor is an Ed25519 public key, not a hash of a secret. A recovery code is a 128-bit secret whose key comes from Q4's derivation. Framework `0x01` accounts run D2 at `t = 1` on that one key. `Δr` and `Δp` are both fixed at 7 days, stated here because `0x01` genesis commits no bounds.

D2. Transition rules, pending SR1:

- `ROTATE` is signed by the active key alone. It is immediate, cannot change policy, and is refused while a recovery or policy change pends. It is intended to close the thief-rotate flood.
- `RECOVER` needs `t` committed factors. It takes effect after `Δr`, installs a new active key, and cancels any pending policy change at any rank.
- A policy change needs the active key plus one committed factor, taking effect after `Δp`. Any change to `Δr` or `Δp` is one. Lengthening applies on acceptance, shortening after `Δp`, and neither touches a pending transition.
- Rank counts the distinct committed factors that signed. The active key adds one only alongside a committed factor, and none against a pending `RECOVER`.
- Higher rank cancels a pending conflict, equal rank cancels both and freezes authority for `Δr`, and lower rank is rejected. Each cancelled initiation doubles that factor set's sequenced backoff.

Compromise condition, by route. Either `t` committed factors outlast `Δr` without a higher-rank cancel. Or the active key plus one committed factor outlasts `Δp` on the policy-change route. A stolen unlocked device holding both satisfies the second, which is Q6.

D3. These stay unrecoverable. Identifier possession, operator action, homeserver action and elapsed time never reach an authority transition, and operators may suspend an account but never reassign it. An `accountId` is permanent under L4, so freezing describes authority, never the identifier. An owner holding the active key alone keeps a rotatable account, but enrolls no new factor while policy is frozen.

D4. Login factors are homeserver-local under L2. The ladder runs strongest first. An authority-signed factor reset of rank at least 1 comes first, so the active key alone cannot trigger one. It notifies every session and device, and allows opposition under R7. The homeserver verifies it against the authenticated key chain, under its own policy. Then a passkey assertion, a signed-in session, then SMS.

D5. The SMS PIN reset becomes P3 for PIN-only accounts. Completion starts a 7-day fresh-factor cooldown. These delays run on identity-service time, as R8 permits. P3 takes no new accounts once clients enroll a committed factor at signup, and is withdrawn at Phase 7. Accounts with a passkey or committed factor get P4 instead: 30 days, with notice and opposition throughout. Its compromise condition is L7's residual plus 30 days.

First shippable step: D5's P3 path in identity-service (SR3). It needs no genesis, no log changes and no new client cryptography, and excludes P4. Accounts with a passkey keep the current reset path until P4 lands at Phase 5.

Still open: the `0x02` defaults for `t` and both delays, proposed as the recovery code alone at `t = 1`, 7 days each, subject to Q6. Also guardians, and PRF timing under O11.

## Blockers for production

Expert questions:

- Q1, distributed systems. Rank is per transition, not per party. Can a party with fewer than `t` factors reach authority, or block the owner indefinitely?
- Q2, distributed systems. Is the equal-rank freeze a denial path beyond L13.4's permission?
- Q3, distributed systems. Does a `Δr` exceeding the detection bound plus a client response window bound a withheld cancel under L12?
- Q4, cryptography. Is HKDF-SHA-256 (RFC 5869) over a WebAuthn `prf` output, or over a 128-bit recovery code, a sound derivation of an Ed25519 seed? Assume a versioned Gua label as `prf` input, with framework id and `accountId` in `info`.
- Q5, cryptography. Does a key from a 128-bit recovery code, published in replicated state, resist offline search, including multi-target search across all accounts?
- Q6, security. Should factors synced by one platform account, or onto the device holding the active key, count as one trust domain, like L8's verifiers? Its answer lifts ADM-008 decision 4's independence gate.
- Q7, security. Should the active key contribute rank at all, given that the policy-change route otherwise lets a stolen unlocked device outrank the owner?

Spikes:

- SR1, a TLA+ model of D2 against five adversary classes. Pass: no counterexample to Q1 to depth 12. Fail: any. Classes:
  - stolen unlocked device with the active key and a synced factor;
  - thief with the active key alone;
  - holder of fewer than `t` factors;
  - censoring sequencer under L12;
  - owner and thief at equal rank.
- SR2, native passkey PRF on iOS and Android, user verification required. Pass: identical output on two devices of one sync account, never leaving native code. Fail: either.
- SR3, D5 in identity-service. Pass: completion from a second device fails, an opposed reset leaves the PIN unchanged, and an unknown phone looks like a known one. Fail: any.

## Implementation implications

- identity-service: replace `/security/pin/reset*`, and add a reset-request table for device binding and opposition state, reusing `deviceNotificationService`. Rollback restores the old endpoints behind a flag; the table is additive.
- Clients: an in-app opposition prompt. The recovery code goes to the synced keychain, and only its derived public key is committed.
- Resolver log: leaf types for rotation, recovery, policy change and cancel, with sequenced time. Homeservers verify authority-signed resets against the key chain at Phase 7.
- Tests: SR1's state table gives golden vectors for the sequencer and both client verifiers.

Migration order: SR3, the `0x02` framework freeze, the D2 leaf types, P4 behind Phase 5's records, then PRF after O11. Phase 3 proceeds under framework `0x01` at `t = 1`.

## Relationship to ADM-001

Labels touched: this record narrows O5 and O6. It implements L13's four requirements, and L4's delegation of transition rules. It uses L11's sequenced time as permitted, scoping R8 to authority and binding transitions. It supplies the delay-and-notification primitive O9 needs, without closing it. P4 is an L3 supersession carried by L6 and L8, adding no binding authority.

Labels relied on unchanged: L2, L3, L5, L7, L8 and L12. The SMS path leaves L7's residual unmitigated. ADM-008's `0x01` layout is untouched, and `0x02` is additive under O2. Nothing locked is reopened.
