package global.gua.resolver.api;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLog;

@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RosterLogController {

    private final JdbcTransparencyLog log;

    public RosterLogController(JdbcTransparencyLog log) {
        this.log = log;
    }

    @GetMapping("/roster/log")
    public LogResponse log() {
        return new LogResponse(log.head(), log.events());
    }

    @GetMapping("/roster/log/consistency")
    public ConsistencyResponse consistency(@RequestParam int first, @RequestParam int second) {
        return new ConsistencyResponse(first, second, log.consistencyProof(first, second));
    }

    public record LogResponse(SignedRoster.LogCheckpoint head, List<TransparencyLog.Event> events) {}

    public record ConsistencyResponse(int first, int second, List<String> proof) {}
}
