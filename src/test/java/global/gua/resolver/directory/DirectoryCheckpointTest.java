package global.gua.resolver.directory;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.roster.JdbcTransparencyLog;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class DirectoryCheckpointTest {

    @Autowired
    private JdbcDirectoryStore directory;

    @Autowired
    private DirectoryCheckpointService service;

    @Autowired
    private JdbcTransparencyLog log;

    @Autowired
    private ResolverProperties props;

    @Test
    void signsAndLogsTheDirectoryCheckpointAndReflectsChanges() {
        int loggedBefore = log.eventsOfType(DirectoryCheckpointService.EVENT_TYPE).size();

        directory.putPhone("+5511999990001", "dev");
        DirectoryCheckpoint.Signed signed = service.publish();

        assertThat(signed.checkpoint().merkleRoot()).isNotBlank();
        assertThat(signed.checkpoint().size()).isGreaterThanOrEqualTo(1);
        assertThat(signed.signatures()).isNotEmpty();

        ResolverProperties.TrustedKey key = props.getAuthority().getTrustedKeys().get(0);
        assertThat(Ed25519.verify(Ed25519.publicKey(key.getPublicKey()),
                DirectoryCheckpointService.canonicalBytes(signed.checkpoint()),
                signed.signatures().get(0).signatureB64())).isTrue();

        int loggedAfterFirst = log.eventsOfType(DirectoryCheckpointService.EVENT_TYPE).size();
        assertThat(loggedAfterFirst).isEqualTo(loggedBefore + 1);

        service.publish();
        assertThat(log.eventsOfType(DirectoryCheckpointService.EVENT_TYPE).size()).isEqualTo(loggedAfterFirst);

        String rootBefore = signed.checkpoint().merkleRoot();
        directory.putUsername("checkpoint-alice", "dev");
        DirectoryCheckpoint.Signed next = service.publish();
        assertThat(next.checkpoint().merkleRoot()).isNotEqualTo(rootBefore);
        assertThat(log.eventsOfType(DirectoryCheckpointService.EVENT_TYPE).size()).isEqualTo(loggedAfterFirst + 1);
    }
}
