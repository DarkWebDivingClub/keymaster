package club.dwdc.keymaster.cli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.file.Path;

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
            case "detach" -> handleDetach();
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

        for (int i = 2; i < args.length; i++) {
            if ("--identity".equals(args[i]) && i + 1 < args.length) {
                identity = args[++i];
            } else if ("--policy".equals(args[i]) && i + 1 < args.length) {
                policy = args[++i];
            }
        }

        if (identity == null) {
            System.err.println("--identity is required");
            return 1;
        }

        JsonObject params = new JsonObject();
        params.addProperty("descriptor", descriptorPath);
        params.addProperty("identity", identity);
        if (policy != null) {
            params.addProperty("policy", policy);
        }

        return rpc("session.attach", params, result -> {
            System.out.println("Attached. Session: " + result.get("sessionId").getAsString());
        });
    }

    private static int handleDetach() {
        return rpc("session.detach", new JsonObject(), result -> {
            System.out.println("Detached.");
        });
    }

    private static int handleStatus() {
        return rpc("session.status", new JsonObject(), result -> {
            boolean attached = result.get("attached").getAsBoolean();
            if (attached) {
                System.out.println("Attached as " + result.get("identity").getAsString());
                System.out.println("Session: " + result.get("sessionId").getAsString());
            } else {
                System.out.println("Not attached.");
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
        System.err.println("  attach <desc.json> --identity <id> [--policy auto]");
        System.err.println("                                Attach to an avatar");
        System.err.println("  detach                        Detach from the avatar");
        System.err.println("  status                        Show session status");
    }

    @FunctionalInterface
    private interface ResultPrinter {
        void print(JsonObject result);
    }
}
