package global.gua.resolver.policy;

/**
 * Notified when a policy source adopts a new routing-policy bundle. The authority uses this to append the
 * policy version's hash to the transparency log, so policy publication is as auditable and equivocation-proof
 * as roster membership. Mirrors register no listener (they only serve verified artifacts).
 */
public interface PolicyPublicationListener {

    void onPolicyAdopted(RoutingPolicyBundle bundle);
}
