package global.gua.resolver.api;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.policy.PolicyTransparencyListener;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

/**
 * Public policy transparency surface: the checkpoint plus the POLICY_PUBLISH history. Policy versions live in
 * the same Merkle log as membership, so a client verifies a policy version was published (inclusion,
 * recomputing the root from {@code /roster/log}) and that the log extends the checkpoint it saw last
 * ({@code /roster/log/consistency}). Consistency proves history, not the absence of a split view
 * (ADM-001 L12). Authority mode only: a mirror does not relay these endpoints.
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class PolicyLogController {

    private final JdbcTransparencyLog log;

    public PolicyLogController(JdbcTransparencyLog log) {
        this.log = log;
    }

    @GetMapping("/policy/log")
    public PolicyLogResponse policyLog() {
        return new PolicyLogResponse(log.head(), log.eventsOfType(PolicyTransparencyListener.EVENT_TYPE));
    }

    public record PolicyLogResponse(SignedRoster.LogCheckpoint head, List<TransparencyLog.Event> policyEvents) {}
}
