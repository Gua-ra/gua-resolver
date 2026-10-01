package global.gua.resolver.roster;

/** Callers always receive an already-verified roster. */
public interface RosterStore {

    SignedRoster current();

    SignedRoster refresh();

    /** As published at GET /roster. On a mirror this is the upstream document verbatim. */
    default SignedRoster served() {
        return current();
    }

    default long unattestedActiveCount() {
        return 0;
    }
}
