package global.gua.resolver.tools;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
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
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.CanonicalMemberEntry;
import global.gua.resolver.roster.MemberAttestation;
import global.gua.resolver.roster.MemberEntrySigner;
import global.gua.resolver.roster.MemberEntryVerifier;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/**
 * Offline signing and checking tool for member roster entries (ADM-007). A homeserver operator runs it with
 * its own member private key to produce the body for {@code POST /authority/roster/{id}/member}; the resolver
 * never holds that key. See docs/runbooks/member-attestation.md.
 *
 * <pre>
 *   sign    --fields fields.json --private-key-file -        [--format attest|member]
 *   rotate  --fields fields.json --private-key-file - --previous-private-key-file - [--format ...]
 *   verify  --roster roster.json [--at 2026-09-11T00:00:00Z] [--max-lifetime-days 400]
 * </pre>
 *
 * <p>A private key is read from a file or, with {@code -}, from standard input, one base64 PKCS#8 key per
 * line; for a rotation reading both from standard input, the new key comes first. There is deliberately no
 * flag that takes a key as an argument value: an argument would land in the shell history and in the process
 * list. The tool prints the attestation, its canonical hash and public metadata, never key material.
 */
public final class MemberEntryTool {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final long DEFAULT_LIFETIME_DAYS = 400;

    private final PrintStream out;
    private final PrintStream err;
    private final BufferedReader stdin;

    public MemberEntryTool(InputStream stdin, PrintStream out, PrintStream err) {
        this.stdin = new BufferedReader(new InputStreamReader(stdin, StandardCharsets.UTF_8));
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new MemberEntryTool(System.in, System.out, System.err).run(args));
    }

    /** @return 0 on success, 2 for a usage problem, 3 when signing or verification fails */
    public int run(String[] args) {
        try {
            if (args.length == 0) {
                usage();
                return 2;
            }
            Map<String, String> options = options(args);
            return switch (args[0]) {
                case "sign" -> sign(options, false);
                case "rotate" -> sign(options, true);
                case "verify" -> verify(options);
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

    private int sign(Map<String, String> options, boolean rotation) throws Exception {
        JsonNode fields = readJson(required(options, "--fields"));
        Homeserver homeserver = homeserver(fields);
        String keyId = text(fields, "keyId", null);
        if (keyId == null) {
            throw new UsageException("fields.keyId is required");
        }
        long sequence = fields.path("sequence").asLong(0);
        if (sequence < 1) {
            throw new UsageException("fields.sequence is required and starts at 1");
        }
        Instant notBefore = fields.hasNonNull("notBefore")
                ? Instant.parse(fields.get("notBefore").asText())
                : Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant notAfter = fields.hasNonNull("notAfter")
                ? Instant.parse(fields.get("notAfter").asText())
                : notBefore.plus(Duration.ofDays(fields.path("lifetimeDays").asLong(DEFAULT_LIFETIME_DAYS)));

        MemberAttestation member = new MemberAttestation(CanonicalMemberEntry.SCHEMA,
                CanonicalMemberEntry.ALG, keyId, sequence, notBefore.truncatedTo(ChronoUnit.MILLIS),
                notAfter.truncatedTo(ChronoUnit.MILLIS), List.of());
        member = MemberEntrySigner.sign(homeserver, member, keyId,
                readPrivateKey(required(options, "--private-key-file"), "member"));

        if (rotation) {
            String previousKeyId = text(fields, "previousKeyId", null);
            if (previousKeyId == null) {
                throw new UsageException("fields.previousKeyId is required for a rotation");
            }
            member = MemberEntrySigner.sign(homeserver, member, previousKeyId,
                    readPrivateKey(required(options, "--previous-private-key-file"), "previous"));
        }

        selfCheck(homeserver, member, fields, rotation);
        String format = options.getOrDefault("--format", "attest");
        out.println(switch (format) {
            case "attest" -> JSON.writerWithDefaultPrettyPrinter().writeValueAsString(attestBody(homeserver, member));
            case "member" -> JSON.writerWithDefaultPrettyPrinter().writeValueAsString(member);
            default -> throw new UsageException("unknown --format " + format + " (attest or member)");
        });
        err.println("entry hash (matches the MEMBER_ATTEST log leaf): "
                + CanonicalMemberEntry.hash(homeserver, member));
        return 0;
    }

    /** Prove locally that the key signed the fields as given, before an operator posts them. */
    private void selfCheck(Homeserver homeserver, MemberAttestation member, JsonNode fields,
                           boolean rotation) {
        MemberEntryVerifier verifier = new MemberEntryVerifier(MemberEntryVerifier.DEFAULT_MAX_LIFETIME);
        Instant at = Instant.now().isBefore(member.notBefore()) ? member.notBefore() : Instant.now();
        MemberEntryVerifier.Result result = verifier.verify(homeserver, member, at);
        if (!result.valid()) {
            throw new IllegalStateException("the signed entry does not verify: " + result.reason()
                    + " (is fields.signingKey the public half of the key you signed with?)");
        }
        if (rotation && fields.hasNonNull("previousSigningKey")) {
            MemberEntryVerifier.Prior prior = new MemberEntryVerifier.Prior(
                    fields.get("previousKeyId").asText(), fields.get("previousSigningKey").asText(),
                    member.sequence() - 1, null);
            MemberEntryVerifier.Result chained = verifier.verify(homeserver, member, at, prior);
            if (!chained.valid()) {
                throw new IllegalStateException("the rotation does not chain to the previous key: "
                        + chained.reason());
            }
        } else if (rotation) {
            err.println("note: fields.previousSigningKey was not supplied, so the previous key's signature "
                    + "was not checked here; the resolver checks it against the key it holds");
        }
    }

    private int verify(Map<String, String> options) throws Exception {
        SignedRoster roster = JSON.readValue(read(required(options, "--roster")), SignedRoster.class);
        Instant at = options.containsKey("--at")
                ? Instant.parse(options.get("--at"))
                : Instant.now();
        long days = Long.parseLong(options.getOrDefault("--max-lifetime-days",
                Long.toString(DEFAULT_LIFETIME_DAYS)));
        MemberEntryVerifier verifier = new MemberEntryVerifier(Duration.ofDays(days));

        int invalid = 0;
        int unattested = 0;
        for (RosterEntry entry : roster.entries()) {
            MemberEntryVerifier.Result result = verifier.verify(entry.homeserver(), entry.member(), at);
            String id = entry.homeserver().id();
            switch (result.outcome()) {
                case VALID -> out.printf("ok         %s sequence=%d keyId=%s hash=%s%n", id,
                        entry.member().sequence(), entry.member().keyId(), result.entryHash());
                case UNATTESTED -> {
                    out.printf("unattested %s status=%s%n", id, entry.status());
                    if (entry.isActive()) {
                        unattested++;
                    }
                }
                case INVALID -> {
                    out.printf("invalid    %s status=%s reason=%s%n", id, entry.status(), result.reason());
                    if (entry.isActive()) {
                        invalid++;
                    }
                }
            }
        }
        out.printf("%d entries, %d ACTIVE unattested, %d ACTIVE invalid, checked at %s%n",
                roster.entries().size(), unattested, invalid, at);
        return invalid > 0 ? 3 : 0;
    }

    private static ObjectNode attestBody(Homeserver homeserver, MemberAttestation member) {
        ObjectNode body = JSON.createObjectNode();
        ObjectNode hs = body.putObject("homeserver");
        hs.put("id", homeserver.id());
        hs.put("serverName", homeserver.serverName());
        hs.put("baseUrl", homeserver.baseUrl());
        hs.put("masIssuer", homeserver.masIssuer());
        hs.put("signingKey", homeserver.signingKey());
        if (homeserver.region() == null) {
            hs.putNull("region");
        } else {
            hs.put("region", homeserver.region());
        }
        hs.put("searchVisibility", homeserver.searchVisibility().name());
        hs.set("searchGroups", JSON.valueToTree(homeserver.searchGroups()));
        body.set("member", JSON.valueToTree(member));
        return body;
    }

    private static Homeserver homeserver(JsonNode fields) {
        List<String> groups = new ArrayList<>();
        fields.path("searchGroups").forEach(g -> groups.add(g.asText()));
        Homeserver.SearchVisibility visibility = Homeserver.SearchVisibility.valueOf(
                text(fields, "searchVisibility", Homeserver.SearchVisibility.GLOBAL.name()));
        return new Homeserver(
                requireField(fields, "id"),
                requireField(fields, "serverName"),
                requireField(fields, "baseUrl"),
                requireField(fields, "masIssuer"),
                fields.hasNonNull("region") ? fields.get("region").asText() : null,
                1, true,
                requireField(fields, "signingKey"),
                visibility, groups);
    }

    /**
     * Read a base64 PKCS#8 Ed25519 private key from a file, or from standard input with {@code -}. The value
     * is validated by loading it, so a wrong file fails here rather than after a signature nobody can use.
     */
    private String readPrivateKey(String source, String label) throws Exception {
        String value;
        if ("-".equals(source)) {
            value = stdin.readLine();
            if (value == null) {
                throw new UsageException("no " + label + " key on standard input");
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
            throw new IllegalStateException("the " + label + " key is not a base64 PKCS#8 Ed25519 key");
        }
        return value;
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

    private String read(String source) throws Exception {
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

    private JsonNode readJson(String source) throws Exception {
        return JSON.readTree(read(source));
    }

    private static String requireField(JsonNode fields, String name) {
        String value = text(fields, name, null);
        if (value == null) {
            throw new UsageException("fields." + name + " is required");
        }
        return value;
    }

    private static String text(JsonNode fields, String name, String fallback) {
        return fields.hasNonNull(name) ? fields.get(name).asText() : fallback;
    }

    private static String required(Map<String, String> options, String flag) {
        String value = options.get(flag);
        if (value == null) {
            throw new UsageException(flag + " is required");
        }
        return value;
    }

    private static Map<String, String> options(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String flag = args[i];
            if (!flag.startsWith("--")) {
                throw new UsageException("unexpected argument: " + flag);
            }
            if (flag.equals("--private-key") || flag.equals("--previous-private-key")) {
                throw new UsageException(flag + " does not exist on purpose: a key passed as an argument "
                        + "lands in the shell history and the process list. Use "
                        + flag + "-file, with - to read it from standard input.");
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
                gua member entry tool (ADM-007). See docs/runbooks/member-attestation.md.

                  sign   --fields FILE --private-key-file FILE|-  [--format attest|member]
                  rotate --fields FILE --private-key-file FILE|-  --previous-private-key-file FILE|-
                  verify --roster FILE|- [--at INSTANT] [--max-lifetime-days N]

                fields FILE is JSON: id, serverName, baseUrl, masIssuer, signingKey (the public half of the
                key you sign with, base64 X.509), keyId, sequence, optional region, searchVisibility,
                searchGroups, notBefore, notAfter or lifetimeDays, and for a rotation previousKeyId plus
                optional previousSigningKey.

                Keys are read from a file or from standard input (-), one base64 PKCS#8 key per line; for a
                rotation reading both from standard input, the new key comes first. Nothing printed on
                standard output contains key material.""");
    }

    private static class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }
}
