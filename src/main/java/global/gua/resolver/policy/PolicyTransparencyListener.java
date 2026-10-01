package global.gua.resolver.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.roster.JdbcTransparencyLog;

@Component
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class PolicyTransparencyListener implements PolicyPublicationListener {

    public static final String EVENT_TYPE = "POLICY_PUBLISH";

    private static final Logger log = LoggerFactory.getLogger(PolicyTransparencyListener.class);

    private final JdbcTransparencyLog transparencyLog;

    public PolicyTransparencyListener(JdbcTransparencyLog transparencyLog) {
        this.transparencyLog = transparencyLog;
    }

    @Override
    public void onPolicyAdopted(RoutingPolicyBundle bundle) {
        if (bundle == null) {
            return;
        }
        String payloadHash = MerkleTree.sha256Hex(CanonicalRoutingPolicy.bytes(bundle));
        if (transparencyLog.hasLeaf(EVENT_TYPE, payloadHash)) {
            return;
        }
        String subject = bundle.policyId() + ":v" + bundle.version();
        transparencyLog.append(EVENT_TYPE, subject, payloadHash);
        log.info("Appended {} to transparency log: {} ({})", EVENT_TYPE, subject, payloadHash);
    }
}
