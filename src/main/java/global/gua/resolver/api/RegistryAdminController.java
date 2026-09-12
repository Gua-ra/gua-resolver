package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.governance.GovernanceException;
import global.gua.resolver.governance.GovernanceJson;
import global.gua.resolver.governance.HomeserverRegistryContent;
import global.gua.resolver.governance.RegistryEpoch;
import global.gua.resolver.governance.RegistryService;
import global.gua.resolver.roster.MemberEntryJson;
import global.gua.resolver.roster.SignedRoster;

/**
 * The operator's half of the epoch ceremony, under {@code /authority/**} and therefore ADMIN-only.
 *
 * <p>{@code GET .../pending} returns the membership this resolver expects the next epoch to carry; the
 * operator signs it offline with the governance key, which never reaches this process, and posts the result
 * to {@code POST .../epoch}. The resolver rebuilds the pending membership again at submission and refuses
 * anything else, so the round trip cannot be used to smuggle in a membership the resolver never proposed.
 *
 * <p>The body is parsed strictly for the same reason a member attestation is: an unknown field or a
 * duplicate key would be content outside the signature, and a signature must cover everything a consumer
 * goes on to read.
 */
@RestController
@RequestMapping("/authority/registry/homeservers")
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class RegistryAdminController {

    private final RegistryService registry;
    private final ObjectMapper json;

    public RegistryAdminController(RegistryService registry, ObjectMapper json) {
        this.registry = registry;
        this.json = json;
    }

    /** The unsigned next epoch: sign this offline, do not compose one by hand. */
    @GetMapping("/pending")
    public RegistryService.PendingEpoch pending() {
        return registry.pending();
    }

    /** Submit the signed epoch together with the content its {@code contentHash} commits to. */
    @PostMapping(path = "/epoch", consumes = MediaType.APPLICATION_JSON_VALUE)
    public SignedRoster submit(@RequestBody byte[] body) {
        JsonNode tree = MemberEntryJson.readTree(json, body);
        RegistryEpoch epoch = GovernanceJson.read(json, tree.path("epoch"), RegistryEpoch.class);
        HomeserverRegistryContent content =
                GovernanceJson.read(json, tree.path("content"), HomeserverRegistryContent.class);
        return registry.commit(epoch, content);
    }

    @ExceptionHandler(GovernanceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onGovernanceError(GovernanceException e) {
        return new ProblemResponse("epoch_rejected", e.getMessage());
    }

    @ExceptionHandler(MemberEntryJson.MalformedMemberEntryException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onMalformedBody(MemberEntryJson.MalformedMemberEntryException e) {
        return new ProblemResponse("malformed_request", e.getMessage());
    }

    public record ProblemResponse(String code, String message) {}
}
