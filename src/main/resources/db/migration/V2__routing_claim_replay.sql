-- Short-lived signed routing claims are bearer-like routing proofs. Store issuer+nonce so multiple
-- resolver replicas sharing the authority DB reject replayed envelopes deterministically.
CREATE TABLE routing_claim_nonce (
    issuer        VARCHAR(512) NOT NULL,
    nonce         VARCHAR(128) NOT NULL,
    expires_at    TIMESTAMP    NOT NULL,
    first_seen_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (issuer, nonce)
);

CREATE INDEX ix_routing_claim_nonce_expires ON routing_claim_nonce (expires_at);
