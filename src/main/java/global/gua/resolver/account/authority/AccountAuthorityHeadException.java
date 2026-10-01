/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

/**
 * A published authority head that was refused, carrying the one reason it was refused for. Thrown by the
 * codec, the ingest verifier, the storage rules and the library verifier alike, so every refusal reaches the
 * caller and the metrics through one path. A refused head is never partially accepted and never repaired.
 */
public class AccountAuthorityHeadException extends RuntimeException {

    private final transient AccountAuthorityHeadRejection rejection;

    public AccountAuthorityHeadException(AccountAuthorityHeadRejection rejection) {
        super(rejection.reason());
        this.rejection = rejection;
    }

    public AccountAuthorityHeadException(AccountAuthorityHeadRejection rejection, String detail) {
        super(rejection.reason() + ": " + detail);
        this.rejection = rejection;
    }

    public AccountAuthorityHeadRejection rejection() {
        return rejection;
    }

    /** The stable code: the API error code and the metric tag value. */
    public String reason() {
        return rejection.reason();
    }
}
