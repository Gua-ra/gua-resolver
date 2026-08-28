package global.gua.resolver.api;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.directory.DirectoryCheckpoint;
import global.gua.resolver.directory.DirectoryCheckpointService;

/**
 * Public, signed directory checkpoint (Merkle root + size, authority-signed, anchored in the transparency
 * log). Clients/mirrors read it to confirm existing-account routing is committed and non-equivocable; the raw
 * phone graph is never exposed. Authority mode only.
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
