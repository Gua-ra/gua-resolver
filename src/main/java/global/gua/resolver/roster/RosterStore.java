package global.gua.resolver.roster;

/**
 * Source of the current, VERIFIED roster. Implementations:
 * <ul>
 *   <li><b>authority</b> — owns the roster, signs it, appends membership changes to the transparency log.</li>
 *   <li><b>mirror</b> — pulls the signed roster from upstream, verifies threshold signatures + log
 *       inclusion, and serves a read-only copy (an institution running its own resolver).</li>
 * </ul>
 *
 * <p>Callers always receive an already-verified roster; verification failures surface as errors here, never
 * as a silently-trusted roster.
 */
public interface RosterStore {

    /** The current verified roster (threshold-signed + transparency-log-checked). */
    SignedRoster current();

    /** Force a refresh from upstream (mirror) or rebuild (authority); returns the new current roster. */
    SignedRoster refresh();
}
