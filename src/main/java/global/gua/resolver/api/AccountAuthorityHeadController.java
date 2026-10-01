/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.api;

import java.time.Instant;
import java.util.Locale;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.account.authority.AccountAuthorityFeature;
import global.gua.resolver.account.authority.AccountAuthorityHeadEnvelope;
import global.gua.resolver.account.authority.AccountAuthorityHeadException;
import global.gua.resolver.account.authority.AccountAuthorityHeadProof;
import global.gua.resolver.account.authority.AccountAuthorityHeadService;
import global.gua.resolver.account.authority.StoredAccountAuthorityHead;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.placement.record.AccountId;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * Publication and read surface for account authority chain heads (ADM-009 decision 12).
 *
 * <p>{@code POST /account/authority/heads} is public and self-authenticating, on the same argument as the
 * placement ingest: the head object names a homeserver, and it is accepted only if it verifies under the roster
 * signing key of that homeserver while that homeserver is ACTIVE. There is no caller identity, no token and no
 * admin role, because there is nothing an unauthenticated caller can do with it. Every presented head either
 * verifies under an active roster key or is refused, the storage rules are reached only after that signature
 * check, so the endpoint is not an oracle for which accounts this node holds heads for, and it is rate limited
 * on top.
 *
 * <p>The reads serve what a verifier needs and nothing else: the stored envelope verbatim, and the proof
 * (envelope, leaf, audit path, checkpoint). Both are keyed on the accountId, which is a 256-bit hash carrying
 * no identifier, and there is deliberately no listing: a caller that does not already hold an accountId learns
 * nothing here, and nobody can enumerate which accounts have adopted. A caller that does hold one learns which
 * homeserver publishes for it and how far its chain has moved, which is the same class of fact the placement
 * read already exposes for the same key.
 *
 * <p>Nothing here is on the resolution path. No routing answer reads a published head, and there is
 * deliberately no flag that would make one.
 */
@RestController
@RequestMapping("/account/authority/heads")
@ConditionalOnExpression(AccountAuthorityFeature.ENABLED)
public class AccountAuthorityHeadController {

    private final AccountAuthorityHeadService heads;
    private final ResolverProperties.AccountAuthority props;

    public AccountAuthorityHeadController(AccountAuthorityHeadService heads,
                                          ResolverProperties properties) {
        this.heads = heads;
        this.props = properties.getAccountAuthority();
    }

    /**
     * Publish a signed authority head. 201 when the account had no published head, 200 when the publishing
     * homeserver moved it forward or re-presented the same bytes.
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @RateLimiter(name = "accountAuthorityHeads")
    public ResponseEntity<PublishResponse> publish(@RequestBody byte[] body) {
        heads.requireIngestEnabled(props.isIngestEnabled());
        AccountAuthorityHeadService.Outcome outcome = heads.publish(body, Instant.now());
        HttpStatus status = outcome == AccountAuthorityHeadService.Outcome.STORED
                ? HttpStatus.CREATED
                : HttpStatus.OK;
        return ResponseEntity.status(status)
                .body(new PublishResponse(outcome.name().toLowerCase(Locale.ROOT)));
    }

    /** The stored signed envelope, verbatim: the bytes that were signed, not a re-encoding of them. */
    @GetMapping("/{accountId}")
    @RateLimiter(name = "accountAuthorityHeads")
    public AccountAuthorityHeadEnvelope head(@PathVariable String accountId) {
        return stored(accountId).envelope();
    }

    /** The envelope plus everything needed to check it against the signed log root. */
    @GetMapping("/{accountId}/proof")
    @RateLimiter(name = "accountAuthorityHeads")
    public AccountAuthorityHeadProof proof(@PathVariable String accountId) {
        return heads.proof(stored(accountId));
    }

    private StoredAccountAuthorityHead stored(String accountId) {
        if (!AccountId.isCanonical(accountId)) {
            throw new BadQueryException("invalid_account_id", "not a canonical accountId");
        }
        return heads.find(accountId)
                .orElseThrow(() -> new BadQueryException("no_authority_head",
                        "no published head is held for that accountId"));
    }

    @ExceptionHandler(AccountAuthorityHeadException.class)
    public ResponseEntity<ProblemResponse> onRejected(AccountAuthorityHeadException e) {
        HttpStatus status = switch (e.rejection()) {
            case AUTHORITY_CONFLICT, PLACEMENT_DISAGREES, STALE_HEAD -> HttpStatus.CONFLICT;
            case INGEST_DISABLED -> HttpStatus.SERVICE_UNAVAILABLE;
            case HEAD_NOT_ANCHORED -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_REQUEST;
        };
        // The message is built from fixed strings only; nothing the caller sent is echoed back.
        return ResponseEntity.status(status).body(new ProblemResponse(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(BadQueryException.class)
    public ResponseEntity<ProblemResponse> onBadQuery(BadQueryException e) {
        HttpStatus status = "no_authority_head".equals(e.code())
                ? HttpStatus.NOT_FOUND
                : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(new ProblemResponse(e.code(), e.getMessage()));
    }

    @ExceptionHandler(RequestNotPermitted.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public ProblemResponse onRateLimited(RequestNotPermitted e) {
        return new ProblemResponse("rate_limited", "too many authority head requests");
    }

    /** A request this endpoint cannot answer as asked; carries a stable code, never the caller's input. */
    static class BadQueryException extends RuntimeException {

        private final String code;

        BadQueryException(String code, String message) {
            super(message);
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    public record PublishResponse(String result) {}

    public record ProblemResponse(String code, String message) {}
}
