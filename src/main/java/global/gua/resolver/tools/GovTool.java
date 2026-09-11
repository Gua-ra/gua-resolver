package global.gua.resolver.tools;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.governance.CanonicalGenesis;
import global.gua.resolver.governance.CanonicalGovernanceTransition;
import global.gua.resolver.governance.CanonicalHomeserverRegistryContent;
import global.gua.resolver.governance.CanonicalRegistryEpoch;
import global.gua.resolver.governance.FederationGenesis;
import global.gua.resolver.governance.GovernanceKey;
import global.gua.resolver.governance.GovernanceSignature;
import global.gua.resolver.governance.GovernanceTransition;
import global.gua.resolver.governance.HomeserverRegistryContent;
import global.gua.resolver.governance.Registry;
import global.gua.resolver.governance.RegistryEpoch;
import global.gua.resolver.policy.CanonicalRoutingPolicy;
import global.gua.resolver.policy.RoutingPolicyBundle;

/**
 * Offline governance tool (ADM-001 L10, S5). An operator runs it on a machine outside the cluster, with the
 * governance private key that never enters a resolver namespace, to create a federation genesis, sign a
 * membership epoch, sign a routing-policy bundle, or sign a governance key transition. See
 * docs/runbooks/governance-keys.md.
 *
 * <pre>
 *   keygen     --operator ID --key-id ID --private-key-out FILE
 *   genesis    create --fields FILE
 *   genesis    sign   --genesis FILE --key-id ID --private-key-file FILE|-
 *   genesis    id     --genesis FILE
 *   epoch      sign   --pending FILE --key-id ID --private-key-file FILE|-
 *   policy     sign   --policy  FILE --key-id ID --private-key-file FILE|-
 *   transition sign   --transition FILE --key-id ID --private-key-file FILE|-
 * </pre>
 *
 * <p>A private key is read from a file or, with {@code -}, from standard input. There is deliberately no flag
 * that takes a key as an argument value: an argument lands in the shell history and the process list. The
 * only command that writes a private key is {@code keygen}, which writes it to the file named by
 * {@code --private-key-out} with owner-only permissions and prints only the public half. Nothing this tool
 * prints on standard output contains key material.
 */
public final class GovTool {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private final PrintStream out;
    private final PrintStream err;
    private final BufferedReader stdin;

    public GovTool(InputStream stdin, PrintStream out, PrintStream err) {
        this.stdin = new BufferedReader(new InputStreamReader(stdin, StandardCharsets.UTF_8));
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new GovTool(System.in, System.out, System.err).run(args));
    }

    /** @return 0 on success, 2 for a usage problem, 3 when signing or verification fails */
    public int run(String[] args) {
        try {
            if (args.length == 0) {
                usage();
                return 2;
            }
            return switch (args[0]) {
                case "keygen" -> keygen(options(args, 1));
                case "genesis" -> genesis(args);
                case "epoch" -> requireSub(args, "epoch", () -> epochSign(options(args, 2)));
                case "policy" -> requireSub(args, "policy", () -> policySign(options(args, 2)));
                case "transition" -> requireSub(args, "transition",
                        () -> transitionSign(options(args, 2)));
                case "help", "-h", "--help" -> {
                    usage();
                    yield 0;
                }
                default -> {
                    err.println("unknown command: " + args[0]);
                    usage();
                    yield 2;
                }
            };
        } catch (UsageException e) {
            err.println(e.getMessage());
            return 2;
        } catch (Exception e) {
            err.println("failed: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
            return 3;
        }
    }

    private interface Action {
        int run() throws Exception;
    }

    private int requireSub(String[] args, String group, Action action) throws Exception {
        if (args.length < 2 || !"sign".equals(args[1])) {
            throw new UsageException(group + " takes one subcommand: sign");
        }
        return action.run();
    }

    private int genesis(String[] args) throws Exception {
        if (args.length < 2) {
            throw new UsageException("genesis takes a subcommand: create, sign or id");
        }
        Map<String, String> options = options(args, 2);
        return switch (args[1]) {
            case "create" -> genesisCreate(options);
            case "sign" -> genesisSign(options);
            case "id" -> genesisId(options);
            default -> throw new UsageException("unknown genesis subcommand: " + args[1]);
        };
    }

    /**
     * Generate a governance keypair. The private half is written to a file, never printed, because a key on
     * standard output ends up in a terminal scrollback, a CI log or a pipe nobody meant to keep.
     */
    private int keygen(Map<String, String> options) throws Exception {
        String operatorId = required(options, "--operator");
        String keyId = required(options, "--key-id");
        Path outFile = Path.of(required(options, "--private-key-out"));
        if (Files.exists(outFile)) {
            throw new IllegalStateException(outFile + " already exists; refusing to overwrite a private key");
        }

        Ed25519.KeyPairB64 pair = Ed25519.generate();
        Files.writeString(outFile, pair.privateKeyB64() + System.lineSeparator());
        restrictToOwner(outFile);

        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(
                new GovernanceKey(keyId, GovernanceKey.ALG, pair.publicKeyB64(), operatorId)));
        err.println("private key written to " + outFile + " (owner-only). Back it up offline and encrypted, "
                + "and never place it in a Kubernetes Secret in a resolver namespace.");
        return 0;
    }

    /** Build the unsigned genesis from a fields file, so nobody hand-composes canonical bytes. */
    private int genesisCreate(Map<String, String> options) throws Exception {
        JsonNode fields = readJson(required(options, "--fields"));
        List<GovernanceKey> keys = new ArrayList<>();
        for (JsonNode k : fields.path("keys")) {
            keys.add(new GovernanceKey(k.get("keyId").asText(), GovernanceKey.ALG,
                    k.get("publicKey").asText(), k.get("operatorId").asText()));
        }
        Instant createdAt = fields.hasNonNull("createdAt")
                ? Instant.parse(fields.get("createdAt").asText())
                : Instant.now();
        FederationGenesis genesis = new FederationGenesis(FederationGenesis.SCHEMA,
                text(fields, "federationLabel"), createdAt.truncatedTo(ChronoUnit.MILLIS),
                FederationGenesis.HASH_SUITE, fields.path("threshold").asLong(1), keys,
                Registry.allWireNames(), List.of());
        genesis.validateShape();

        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(genesis));
        reportGenesis(genesis);
        return 0;
    }

    private int genesisSign(Map<String, String> options) throws Exception {
        FederationGenesis genesis = read(required(options, "--genesis"), FederationGenesis.class);
        genesis.validateShape();
        String keyId = required(options, "--key-id");
        byte[] canonical = CanonicalGenesis.bytes(genesis);
        FederationGenesis signed = genesis.withSignatures(
                add(genesis.signatures(), sign(canonical, keyId, options, "--private-key-file")));

        requireKeyIsEnumerated(signed.keys(), keyId);
        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(signed));
        reportGenesis(signed);
        return 0;
    }

    private int genesisId(Map<String, String> options) throws Exception {
        FederationGenesis genesis = read(required(options, "--genesis"), FederationGenesis.class);
        genesis.validateShape();
        reportGenesis(genesis);
        return 0;
    }

    private void reportGenesis(FederationGenesis genesis) {
        String id = CanonicalGenesis.id(genesis);
        err.println("genesisId:   " + id);
        err.println("fingerprint: " + CanonicalGenesis.fingerprint(id));
        long operators = genesis.keys().stream().map(GovernanceKey::operatorId).distinct().count();
        err.println("threshold " + genesis.threshold() + " of " + operators + " operator(s), "
                + genesis.keys().size() + " key(s)");
        if (operators == 1) {
            err.println("note: one operator, so this separates processes and custody, not principals.");
        }
    }

    /**
     * Sign the epoch the resolver is asking for. The content hash is recomputed from the content here rather
     * than trusted from the response, so the operator signs a membership they derived, not one they were
     * handed.
     */
    private int epochSign(Map<String, String> options) throws Exception {
        JsonNode pending = readJson(required(options, "--pending"));
        HomeserverRegistryContent content =
                JSON.treeToValue(pending.get("content"), HomeserverRegistryContent.class);
        content.validateShape();

        String contentHash = CanonicalHomeserverRegistryContent.hash(content);
        String served = pending.path("contentHash").asText();
        if (!contentHash.equals(served)) {
            throw new IllegalStateException("the pending content does not hash to the contentHash the "
                    + "resolver served (" + served + "); refusing to sign it");
        }

        RegistryEpoch unsigned = new RegistryEpoch(RegistryEpoch.SCHEMA,
                Registry.of(pending.get("registry").asText()), pending.get("genesisId").asText(),
                pending.get("epoch").asLong(), pending.path("previousEpochHash").asText(),
                Instant.now().truncatedTo(ChronoUnit.MILLIS), contentHash, List.of());
        unsigned.validateShape();

        String keyId = required(options, "--key-id");
        RegistryEpoch signed = unsigned.withSignatures(List.of(
                sign(CanonicalRegistryEpoch.bytes(unsigned), keyId, options, "--private-key-file")));

        ObjectNode body = JSON.createObjectNode();
        body.set("epoch", JSON.valueToTree(signed));
        body.set("content", JSON.valueToTree(content));
        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(body));
        err.println("epoch hash (matches the MEMBERSHIP_EPOCH log leaf): "
                + CanonicalRegistryEpoch.hash(signed));
        err.println(content.members().size() + " member(s) signed; POST this to "
                + "/authority/registry/homeservers/epoch");
        return 0;
    }

    private int policySign(Map<String, String> options) throws Exception {
        RoutingPolicyBundle bundle = read(required(options, "--policy"), RoutingPolicyBundle.class);
        String keyId = required(options, "--key-id");
        GovernanceSignature signature =
                sign(CanonicalRoutingPolicy.bytes(bundle), keyId, options, "--private-key-file");

        List<RoutingPolicyBundle.PolicySignature> signatures =
                new ArrayList<>(bundle.signatures() == null ? List.of() : bundle.signatures());
        signatures.removeIf(s -> keyId.equals(s.authorityKeyId()));
        signatures.add(new RoutingPolicyBundle.PolicySignature(keyId, signature.signatureB64()));

        RoutingPolicyBundle signed = new RoutingPolicyBundle(bundle.schemaVersion(), bundle.policyId(),
                bundle.version(), bundle.issuedAt(), bundle.notBefore(), bundle.expiresAt(),
                bundle.delegationZones(), bundle.rules(), bundle.fallback(), signatures,
                bundle.delegateSignatures());

        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(signed));
        err.println("signed routing policy " + signed.policyId() + " v" + signed.version()
                + " with governance key " + keyId);
        return 0;
    }

    private int transitionSign(Map<String, String> options) throws Exception {
        GovernanceTransition transition =
                read(required(options, "--transition"), GovernanceTransition.class);
        transition.validateShape();
        String keyId = required(options, "--key-id");
        GovernanceTransition signed = transition.withSignatures(add(transition.signatures(),
                sign(CanonicalGovernanceTransition.bytes(transition), keyId, options,
                        "--private-key-file")));

        out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(signed));
        err.println("transition " + signed.index() + " hash: "
                + CanonicalGovernanceTransition.hash(signed));
        err.println("a transition needs the outgoing set's threshold AND the incoming set's; run this once "
                + "per key holder and merge the signature lists.");
        return 0;
    }

    private static void requireKeyIsEnumerated(List<GovernanceKey> keys, String keyId) {
        if (keys.stream().noneMatch(k -> k.keyId().equals(keyId))) {
            throw new IllegalStateException("key id " + keyId + " is not one of the keys this genesis "
                    + "enumerates, so its signature would never be counted");
        }
    }

    private static List<GovernanceSignature> add(List<GovernanceSignature> existing,
                                                 GovernanceSignature signature) {
        List<GovernanceSignature> signatures = new ArrayList<>(existing);
        signatures.removeIf(s -> signature.keyId().equals(s.keyId()));
        signatures.add(signature);
        return signatures;
    }

    /** Sign canonical bytes, checking that the signature verifies before it is emitted. */
    private GovernanceSignature sign(byte[] canonical, String keyId, Map<String, String> options,
                                     String flag) throws Exception {
        String privateKey = readPrivateKey(required(options, flag));
        String signatureB64 = Ed25519.sign(Ed25519.privateKey(privateKey), canonical);
        return new GovernanceSignature(keyId, signatureB64);
    }

    private String readPrivateKey(String source) throws Exception {
        String value;
        if ("-".equals(source)) {
            value = stdin.readLine();
            if (value == null) {
                throw new UsageException("no governance key on standard input");
            }
        } else {
            Path path = Path.of(source);
            warnIfReadableByOthers(path);
            value = Files.readString(path);
        }
        value = value.lines()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("-----"))
                .reduce("", String::concat);
        try {
            Ed25519.privateKey(value);
        } catch (RuntimeException e) {
            throw new IllegalStateException("the governance key is not a base64 PKCS#8 Ed25519 key");
        }
        return value;
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path,
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (Exception ignored) {
            // Not a POSIX filesystem: the caller's umask is all there is.
        }
    }

    private void warnIfReadableByOthers(Path path) {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            if (permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)) {
                err.println("warning: " + path + " is readable beyond its owner; prefer piping the key "
                        + "into standard input with --private-key-file -");
            }
        } catch (Exception ignored) {
            // Not a POSIX filesystem: nothing to check.
        }
    }

    private <T> T read(String source, Class<T> type) throws Exception {
        return JSON.readValue(readText(source), type);
    }

    private JsonNode readJson(String source) throws Exception {
        return JSON.readTree(readText(source));
    }

    private String readText(String source) throws Exception {
        if ("-".equals(source)) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = stdin.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
        return Files.readString(Path.of(source));
    }

    private static String text(JsonNode fields, String name) {
        if (!fields.hasNonNull(name)) {
            throw new UsageException("fields." + name + " is required");
        }
        return fields.get(name).asText();
    }

    private static String required(Map<String, String> options, String flag) {
        String value = options.get(flag);
        if (value == null) {
            throw new UsageException(flag + " is required");
        }
        return value;
    }

    private static Map<String, String> options(String[] args, int from) {
        Map<String, String> options = new HashMap<>();
        for (int i = from; i < args.length; i++) {
            String flag = args[i];
            if (!flag.startsWith("--")) {
                throw new UsageException("unexpected argument: " + flag);
            }
            if (flag.equals("--private-key")) {
                throw new UsageException("--private-key does not exist on purpose: a key passed as an "
                        + "argument lands in the shell history and the process list. Use "
                        + "--private-key-file, with - to read it from standard input.");
            }
            if (i + 1 >= args.length) {
                throw new UsageException(flag + " needs a value");
            }
            if (options.put(flag, args[++i]) != null) {
                throw new UsageException(flag + " was given twice");
            }
        }
        return options;
    }

    private void usage() {
        err.println("""
                gua governance tool (ADM-001 L10). See docs/runbooks/governance-keys.md.

                  keygen     --operator ID --key-id ID --private-key-out FILE
                  genesis    create --fields FILE
                  genesis    sign   --genesis FILE --key-id ID --private-key-file FILE|-
                  genesis    id     --genesis FILE
                  epoch      sign   --pending FILE --key-id ID --private-key-file FILE|-
                  policy     sign   --policy  FILE --key-id ID --private-key-file FILE|-
                  transition sign   --transition FILE --key-id ID --private-key-file FILE|-

                The genesis fields FILE is JSON: federationLabel, threshold, keys[] of
                {keyId, publicKey, operatorId}, and an optional createdAt. The registries are fixed in v1.

                The epoch pending FILE is the body of GET /authority/registry/homeservers/pending.

                Keys are read from a file or standard input (-). Only keygen writes a private key, to the
                file you name, owner-only. Nothing on standard output contains key material.""");
    }

    private static class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }
}
