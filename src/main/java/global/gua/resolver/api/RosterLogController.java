package global.gua.resolver.api;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

/**
 * Public transparency-log surface (§5): anyone — clients, mirrors, auditors — can read the current
 * checkpoint, the event history, and a consistency proof between two tree sizes. Mirrors call
 * {@code /roster/log/consistency} to verify each pulled roster is an append-only extension of the last
 * (no rewritten history / split view). Authority mode only; mirrors relay from upstream.
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RosterLogController {

    private final JdbcTransparencyLog log;

    public RosterLogController(JdbcTransparencyLog log) {
        this.log = log;
    }

    /** Current checkpoint + the full event history (auditors verify entries against the roster). */
    @GetMapping("/roster/log")
    public LogResponse log() {
        return new LogResponse(log.head(), log.events());
    }

    /** Consistency proof that the tree of {@code second} leaves extends the tree of {@code first} leaves. */
    @GetMapping("/roster/log/consistency")
    public ConsistencyResponse consistency(@RequestParam int first, @RequestParam int second) {
        return new ConsistencyResponse(first, second, log.consistencyProof(first, second));
    }

    public record LogResponse(SignedRoster.LogCheckpoint head, List<TransparencyLog.Event> events) {}

    public record ConsistencyResponse(int first, int second, List<String> proof) {}
}
