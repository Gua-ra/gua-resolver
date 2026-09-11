package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.directory.DirectoryCheckpoint;
import global.gua.resolver.directory.DirectoryCheckpointService;

/**
 * Public, signed directory checkpoint (Merkle root + size, authority-signed, anchored in the transparency
 * log). Clients and mirrors read it to learn which directory state the authority node has committed to. It
 * is an assertion by the signer (ADM-001 L11): no per-entry inclusion proof is served, so an individual
 * mapping cannot be checked against it. The raw phone graph is not exposed here, though
 * {@code POST /resolve} answers existence for any number (ADM-001 L16). Authority mode only.
 */
@RestController
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class DirectoryCheckpointController {

    private final DirectoryCheckpointService checkpoints;

    public DirectoryCheckpointController(DirectoryCheckpointService checkpoints) {
        this.checkpoints = checkpoints;
    }

    @GetMapping("/directory/checkpoint")
    public DirectoryCheckpoint.Signed checkpoint() {
        return checkpoints.current();
    }
}
