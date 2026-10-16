package club.dwdc.keymaster.cli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * KeyMaster CLI — {@code km-cli} entry point.
 *
 * <p>Thin client that sends JSON-RPC commands to the KeyMaster daemon
 * over a Unix domain socket.
 *
 * <h3>Commands</h3>
 * <ul>
 *   <li>{@code identity create <id>} — create identity, store pubkey</li>
 *   <li>{@code identity list} — list stored identities</li>
 *   <li>{@code identity show <id>} — show identity details</li>
 *   <li>{@code attach <descriptor.json> --identity <id> [--policy auto]} — attach to avatar</li>
 *   <li>{@code detach} — detach from avatar</li>
 *   <li>{@code status} — show session status</li>
 * </ul>
 */
public class Main {

    public static void main(String[] args) {
        int exitCode = run(args);
        System.exit(exitCode);
    }

    /**
     * Run the CLI with the given arguments.
     *
     * @return exit code (0 = success, 1 = error)
     */
    static int run(String[] args) {
        if (args.length == 0) {
            printUsage();
            return 1;
        }

        return switch (args[0]) {
            case "identity" -> handleIdentity(args);
            case "attach" -> handleAttach(args);
            case "detach" -> handleDetach(args);
            case "status" -> handleStatus();
            default -> {
                System.err.println("Unknown command: " + args[0]);
                printUsage();
                yield 1;
            }
        };
    }

    private static int handleIdentity(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: km-cli identity <create|list|show> [args]");
            return 1;
        }

        return switch (args[1]) {
            case "create" -> identityCreate(args);
            case "list" -> identityList();
            case "show" -> identityShow(args);
            default -> {
                System.err.println("Unknown identity command: " + args[1]);
                yield 1;
            }
        };
    }

    private static int identityCreate(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: km-cli identity create <identity>");
            return 1;
        }

        JsonObject params = new JsonObject();
        params.addProperty("identity", args[2]);

        return rpc("identity.create", params, result -> {
            System.out.println("Created identity: " + result.get("identity").getAsString());
            System.out.println("Public key: " + result.get("pubkey").getAsString());
        });
    }

    private static int identityList() {
        return rpc("identity.list", new JsonObject(), result -> {
            JsonArray identities = result.getAsJsonArray("identities");
            if (identities.isEmpty()) {
                System.out.println("No identities stored.");
                return;
            }
            for (var entry : identities) {
                JsonObject obj = entry.getAsJsonObject();
                System.out.println(obj.get("identity").getAsString() + "  " +
                        obj.get("pubkey").getAsString());
            }
        });
    }

    private static int identityShow(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: km-cli identity show <identity>");
            return 1;
        }

        JsonObject params = new JsonObject();
        params.addProperty("identity", args[2]);

        return rpc("identity.show", params, result -> {
            System.out.println("Identity:   " + result.get("identity").getAsString());
            System.out.println("Public key: " + result.get("pubkey").getAsString());
        });
    }

    private static int handleAttach(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: km-cli attach <descriptor.json> --identity <id> [--policy auto]");
            return 1;
        }

        String descriptorPath = args[1];
        String identity = null;
        String policy = null;
        String realmName = null;
        Integer joinRealmId = null;
        JsonArray identities = new JsonArray();

        for (int i = 2; i < args.length; i++) {
            if ("--identity".equals(args[i]) && i + 1 < args.length) {
                identity = args[++i];
            } else if ("--policy".equals(args[i]) && i + 1 < args.length) {
                policy = args[++i];
            } else if ("--realm-name".equals(args[i]) && i + 1 < args.length) {
                realmName = args[++i];
            } else if ("--realm".equals(args[i]) && i + 1 < args.length) {
                joinRealmId = Integer.parseInt(args[++i]);
            } else if ("--also".equals(args[i]) && i + 1 < args.length) {
                identities.add(alsoIdentity(args[++i]));
            }
        }

        if (joinRealmId == null && identity == null) {
            System.err.println("--identity is required (or --realm <id> to join an existing realm)");
            return 1;
        }

        JsonObject params = new JsonObject();
        params.addProperty("descriptor", descriptorPath);
        if (joinRealmId != null) {
            params.addProperty("realm_id", joinRealmId);
        } else {
            params.addProperty("identity", identity);
            if (realmName != null) {
                params.addProperty("realm_name", realmName);
            }
            if (!identities.isEmpty()) {
                params.add("identities", identities);
            }
        }
        if (policy != null) {
            params.addProperty("policy", policy);
        }

        return rpc("session.attach", params, result -> {
            System.out.println("Attached to realm " + result.get("realmId").getAsInt()
                    + " (" + result.get("realmName").getAsString() + ")"
                    + " as connector " + result.get("connectorId").getAsInt());
            System.out.println("Identities: " + joinList(result.getAsJsonArray("identities")));
            System.out.println("Session: " + result.get("sessionId").getAsString());
        });
    }

    /**
     * Parse an {@code --also} value: {@code bob@example.com} for all protocols,
     * or {@code bob@example.com:ssh,gpg} to serve only those.
     */
    private static JsonElement alsoIdentity(String value) {
        int colon = value.indexOf(':');
        if (colon < 0) {
            return new JsonPrimitive(value);
        }
        JsonObject entry = new JsonObject();
        entry.addProperty("identity", value.substring(0, colon));
        JsonArray protocols = new JsonArray();
        for (String protocol : value.substring(colon + 1).split(",")) {
            if (!protocol.isBlank()) {
                protocols.add(protocol.trim());
            }
        }
        entry.add("protocols", protocols);
        return entry;
    }

    private static String joinList(JsonArray array) {
        List<String> values = new ArrayList<>();
        array.forEach(element -> values.add(element.getAsString()));
        return String.join(", ", values);
    }

    private static int handleDetach(String[] args) {
        JsonObject params = new JsonObject();
        for (int i = 1; i < args.length; i++) {
            if ("--realm".equals(args[i]) && i + 1 < args.length) {
                params.addProperty("realm_id", Integer.parseInt(args[++i]));
            } else if ("--connector".equals(args[i]) && i + 1 < args.length) {
                params.addProperty("connector_id", Integer.parseInt(args[++i]));
            }
        }
        return rpc("session.detach", params, result -> {
            System.out.println("Detached.");
        });
    }

    private static int handleStatus() {
        return rpc("session.status", new JsonObject(), result -> {
            if (!result.get("attached").getAsBoolean()) {
                System.out.println("Not attached.");
                return;
            }
            for (JsonElement element : result.getAsJsonArray("realms")) {
                JsonObject realm = element.getAsJsonObject();
                List<String> connectors = new ArrayList<>();
                realm.getAsJsonArray("connectors")
                        .forEach(c -> connectors.add(String.valueOf(c.getAsInt())));
                System.out.println("Realm " + realm.get("realmId").getAsInt()
                        + " (" + realm.get("realmName").getAsString() + ")");
                System.out.println("  Identities: "
                        + joinList(realm.getAsJsonArray("identities")));
                System.out.println("  Connectors: " + String.join(", ", connectors));
            }
        });
    }

    /**
     * Send an RPC request and handle the response.
     */
    private static int rpc(String method, JsonObject params, ResultPrinter printer) {
        Path socketPath = resolveSocketPath();

        try (DaemonClient client = DaemonClient.connect(socketPath)) {
            JsonObject response = client.sendRequest(method, params);

            if (response.has("error")) {
                JsonObject error = response.getAsJsonObject("error");
                System.err.println("Error: " + error.get("message").getAsString());
                return 1;
            }

            printer.print(response.getAsJsonObject("result"));
            return 0;
        } catch (DaemonClient.DaemonNotRunningException e) {
            System.err.println("Daemon not running. Start with: km-daemon");
            return 1;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    static Path resolveSocketPath() {
        String envSocket = System.getenv("KM_SOCKET");
        if (envSocket != null && !envSocket.isEmpty()) {
            return Path.of(envSocket);
        }

        String xdgRuntime = System.getenv("XDG_RUNTIME_DIR");
        if (xdgRuntime != null && !xdgRuntime.isEmpty()) {
            return Path.of(xdgRuntime, "keymaster.sock");
        }

        return Path.of(System.getProperty("java.io.tmpdir"), "keymaster.sock");
    }

    private static void printUsage() {
        System.err.println("Usage: km-cli <command> [args]");
        System.err.println();
        System.err.println("Commands:");
        System.err.println("  identity create <id>          Create a new identity");
        System.err.println("  identity list                 List all identities");
        System.err.println("  identity show <id>            Show identity details");
        System.err.println("  attach <desc.json> --identity <id> [--realm-name <name>]");
        System.err.println("                     [--also <id>[:ssh,gpg,nostr]]... [--policy auto]");
        System.err.println("                                Create a realm and attach to an avatar");
        System.err.println("  attach <desc.json> --realm <realmId> [--policy auto]");
        System.err.println("                                Attach another avatar to an existing realm");
        System.err.println("  detach [--realm <realmId> [--connector <connectorId>]]");
        System.err.println("                                Detach one connector, one realm, or all");
        System.err.println("  status                        Show realms and their connectors");
    }

    @FunctionalInterface
    private interface ResultPrinter {
        void print(JsonObject result);
    }
}
