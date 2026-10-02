package global.gua.resolver.roster;

/**
 * Source of the current, verified roster. Implementations:
 * <ul>
 *   <li><b>authority</b>: the node that signs and serves the roster in AUTHORITY mode and appends membership
 *       changes to the transparency log.</li>
 *   <li><b>mirror</b>: pulls the signed roster from upstream, verifies threshold signatures and log
 *       consistency, and serves a read-only copy.</li>
 * </ul>
 *
 * <p>Callers always receive an already-verified roster; verification failures surface as errors here, never
 * as a silently trusted roster.
 */
public interface RosterStore {

    /** The current verified roster (threshold-signed and transparency-log-checked). */
    SignedRoster current();

    /** Force a refresh from upstream (mirror) or rebuild (authority); returns the new current roster. */
    SignedRoster refresh();

    /**
     * The roster as published at {@code GET /roster}. On an authority this is {@link #current()}, which was
     * signed over exactly the entries it serves. On a mirror it is the upstream document verbatim, so a
     * client can still check the upstream signature over it, while {@link #current()} is this node's verified
     * view of it (entries whose member self-signature failed are dropped from that view under
     * {@code gua.resolver.roster.require-member-signature}).
     */
    default SignedRoster served() {
        return current();
    }

    /**
     * ACTIVE entries with no valid member self-signature, whether they are still served (transition flag off)
     * or excluded (flag on). The operator watches this reach zero before flipping the flag, and alerts on it
     * afterwards.
     */
    default long unattestedActiveCount() {
        return 0;
    }
}
