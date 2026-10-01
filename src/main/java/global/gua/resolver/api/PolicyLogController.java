package global.gua.resolver.api;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.policy.PolicyTransparencyListener;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

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
