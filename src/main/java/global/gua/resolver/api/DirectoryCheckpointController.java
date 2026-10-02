package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.directory.DirectoryCheckpoint;
import global.gua.resolver.directory.DirectoryCheckpointService;

/**
 * Public, signed directory checkpoint (Merkle root plus size, authority-signed, anchored in the transparency
 * log). Clients and mirrors read it to learn which directory state the authority node has committed to. It
 * is an assertion by the signer: no per-entry inclusion proof is served, so an individual mapping cannot be
 * checked against it. Authority mode only.
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
