/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

/**
 * The single condition every account-authority-head bean is gated on (ADM-009 decision 12, gate 1).
 *
 * <p>Published heads are AUTHORITY-node state, and the whole feature is off unless a deployment turns it on.
 * With the shipped defaults none of these beans exists, no path is mapped and no table is read, so a resolver
 * behaves exactly as it did before this phase: no ACCOUNT_AUTHORITY leaf can be appended, which matters more
 * here than elsewhere because the log size is the roster version and every leaf moves new-account fallback
 * placement (ADM-001 L6). The ingest path carries a second flag of its own
 * ({@code gua.resolver.account-authority.ingest-enabled}), so reads and writes roll out separately and the
 * rollback for either is the flag, with the table left in place.
 *
 * <p>The library verifier is deliberately not gated: it is a pure function a client ports, holds no state and
 * mounts nothing. Nothing in this phase reads a published head on the resolution path, and there is no flag
 * that would make one.
 */
public final class AccountAuthorityFeature {

    /** AUTHORITY mode AND {@code gua.resolver.account-authority.enabled}; both keep their old defaults. */
    public static final String ENABLED =
            "'${gua.resolver.mode:AUTHORITY}' == 'AUTHORITY' "
                    + "and ${gua.resolver.account-authority.enabled:false}";

    private AccountAuthorityFeature() {}
}
