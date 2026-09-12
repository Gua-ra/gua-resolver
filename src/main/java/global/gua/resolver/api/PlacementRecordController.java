package global.gua.resolver.api;

import java.time.Instant;
import java.util.List;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.placement.record.AccountId;
import global.gua.resolver.placement.record.PlacementFeature;
import global.gua.resolver.placement.record.PlacementRecordEnvelope;
import global.gua.resolver.placement.record.PlacementRecordException;
import global.gua.resolver.placement.record.PlacementRecordService;
import global.gua.resolver.placement.record.StoredPlacementRecord;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

/**
 * Ingest and read surface for generation-1 placement records (migration plan Phase 4).
 *
 * <p>{@code POST /placement/records} is public and self-authenticating: the record names a homeserver, and
 * it is accepted only if it verifies under the roster signing key of that homeserver while that homeserver
 * is ACTIVE. There is no caller identity, no token and no admin role, because there is nothing an
 * unauthenticated caller can do with it. Every presented record either verifies under an active roster key
 * or is refused, the storage rules are reached only after that signature check, so the endpoint is not an
 * oracle for what is already stored, and it is rate limited on top.
 *
 * <p>The reads serve what the shadow reconciler compares against: one record by accountId, and a paged
 * listing per homeserver. An accountId is a 256-bit hash and carries no identifier, so neither read exposes
 * a phone, a phone hash or a Matrix user id. This is still new public state and ADM-008 gates production
 * publishing on the ADM-001 L16 review.
 *
 * <p>Nothing here is on the resolution path. No routing answer reads a placement record in this phase, and
 * there is deliberately no flag that would make one.
 */
@RestController
@RequestMapping("/placement/records")
@ConditionalOnExpression(PlacementFeature.ENABLED)
public class PlacementRecordController {

    private final PlacementRecordService records;
    private final ResolverProperties.Placement props;

    public PlacementRecordController(PlacementRecordService records, ResolverProperties properties) {
        this.records = records;
        this.props = properties.getPlacement();
    }

    /**
     * Present a signed placement record. 201 when the accountId had no home, 200 when the holding
     * homeserver re-issued or re-presented the same bytes.
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @RateLimiter(name = "placementRecords")
    public ResponseEntity<IngestResponse> ingest(@RequestBody byte[] body) {
        records.requireIngestEnabled(props.isIngestEnabled());
        PlacementRecordService.Outcome outcome = records.ingest(body, Instant.now());
        HttpStatus status = outcome == PlacementRecordService.Outcome.STORED
                ? HttpStatus.CREATED
                : HttpStatus.OK;
        return ResponseEntity.status(status)
                .body(new IngestResponse(outcome.name().toLowerCase(Locale.ROOT)));
    }

    /** The stored signed envelope, verbatim: the bytes that were signed, not a re-encoding of them. */
    @GetMapping("/{accountId}")
    @RateLimiter(name = "placementRecords")
    public PlacementRecordEnvelope record(@PathVariable String accountId) {
        if (!AccountId.isCanonical(accountId)) {
            throw new BadQueryException("invalid_account_id", "not a canonical accountId");
        }
        return records.find(accountId)
                .map(StoredPlacementRecord::envelope)
                .orElseThrow(() -> new BadQueryException("no_placement_record",
                        "no record is held for that accountId"));
    }

    /**
     * One page of a homeserver's records, for reconciliation. The homeserver id is required: there is no
     * unbounded listing of every record this node holds.
     */
    @GetMapping
    @RateLimiter(name = "placementRecords")
    public PageResponse list(@RequestParam(required = false) String homeserverId,
                             @RequestParam(required = false) String cursor,
                             @RequestParam(required = false) Integer limit) {
        if (homeserverId == null || homeserverId.isBlank()) {
            throw new BadQueryException("homeserver_id_required", "homeserverId is required");
        }
        if (cursor != null && !cursor.isBlank() && !AccountId.isCanonical(cursor)) {
            throw new BadQueryException("invalid_cursor", "a cursor is an accountId");
        }
        int size = limit == null
                ? props.getDefaultPageSize()
                : Math.clamp(limit, 1, props.getMaxPageSize());
        List<StoredPlacementRecord> page = records.listByHomeserver(homeserverId, cursor, size);
        List<PageItem> items = page.stream()
                .map(r -> new PageItem(r.accountId(), r.homeserverId(), r.origin().name(),
                        r.recordB64(), r.signatureB64()))
                .toList();
        String next = page.size() == size ? page.get(page.size() - 1).accountId() : null;
        return new PageResponse(homeserverId, items, next);
    }

    @ExceptionHandler(PlacementRecordException.class)
    public ResponseEntity<ProblemResponse> onRejected(PlacementRecordException e) {
        HttpStatus status = switch (e.rejection()) {
            case PLACEMENT_CONFLICT, STALE_REISSUE -> HttpStatus.CONFLICT;
            case INGEST_DISABLED -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_REQUEST;
        };
        // The message is built from fixed strings only; nothing the caller sent is echoed back.
        return ResponseEntity.status(status).body(new ProblemResponse(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(BadQueryException.class)
    public ResponseEntity<ProblemResponse> onBadQuery(BadQueryException e) {
        HttpStatus status = "no_placement_record".equals(e.code())
                ? HttpStatus.NOT_FOUND
                : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(new ProblemResponse(e.code(), e.getMessage()));
    }

    @ExceptionHandler(RequestNotPermitted.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public ProblemResponse onRateLimited(RequestNotPermitted e) {
        return new ProblemResponse("rate_limited", "too many placement record requests");
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

    public record IngestResponse(String result) {}

    public record PageItem(String accountId, String homeserverId, String origin, String record,
                           String signature) {}

    public record PageResponse(String homeserverId, List<PageItem> records, String nextCursor) {}

    public record ProblemResponse(String code, String message) {}
}
