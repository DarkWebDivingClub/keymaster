package club.dwdc.keymaster.cli;

import club.dwdc.keymaster.daemon.DaemonServer;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    @TempDir
    static Path tempDir;

    private static DaemonServer server;
    private static Path socketPath;

    @BeforeAll
    static void startDaemon() throws Exception {
        socketPath = tempDir.resolve("test-km.sock");

        // Stub handler that echoes method names and handles basic identity ops
        server = new DaemonServer(socketPath, (method, params) -> {
            JsonObject result = new JsonObject();
            return switch (method) {
                case "identity.create" -> {
                    result.addProperty("identity", params.get("identity").getAsString());
                    result.addProperty("pubkey", "a".repeat(64));
                    yield result;
                }
                case "identity.list" -> {
                    result.add("identities", new com.google.gson.JsonArray());
                    yield result;
                }
                case "identity.show" -> {
                    if (params.has("identity") && "alice@atlanta.com".equals(params.get("identity").getAsString())) {
                        result.addProperty("identity", "alice@atlanta.com");
                        result.addProperty("pubkey", "a".repeat(64));
                        yield result;
                    }
                    result.addProperty("error", "Identity not found: " + params.get("identity").getAsString());
                    yield result;
                }
                case "session.status" -> {
                    result.addProperty("attached", false);
                    yield result;
                }
                case "session.detach" -> {
                    result.addProperty("status", "ok");
                    yield result;
                }
                default -> {
                    result.addProperty("error", "unknown method: " + method);
                    yield result;
                }
            };
        });

        server.start();
    }

    @AfterAll
    static void stopDaemon() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void unknownCommandReturnsOne() {
        int exit = Main.run(new String[]{"bogus"});
        assertEquals(1, exit);
    }

    @Test
    void noArgsReturnsOne() {
        int exit = Main.run(new String[]{});
        assertEquals(1, exit);
    }

    @Test
    void identityCreateViaRpc() throws Exception {
        try (DaemonClient client = DaemonClient.connect(socketPath)) {
            JsonObject params = new JsonObject();
            params.addProperty("identity", "alice@atlanta.com");

            JsonObject response = client.sendRequest("identity.create", params);
            assertTrue(response.has("result"), "Should have result: " + response);
            JsonObject result = response.getAsJsonObject("result");
            assertEquals("alice@atlanta.com", result.get("identity").getAsString());
            assertEquals(64, result.get("pubkey").getAsString().length());
        }
    }

    @Test
    void identityListViaRpc() throws Exception {
        try (DaemonClient client = DaemonClient.connect(socketPath)) {
            JsonObject response = client.sendRequest("identity.list", new JsonObject());
            assertTrue(response.has("result"));
            assertTrue(response.getAsJsonObject("result").has("identities"));
        }
    }

    @Test
    void statusWhenNotAttached() throws Exception {
        try (DaemonClient client = DaemonClient.connect(socketPath)) {
            JsonObject response = client.sendRequest("session.status", new JsonObject());
            assertTrue(response.has("result"));
            assertFalse(response.getAsJsonObject("result").get("attached").getAsBoolean());
        }
    }

    @Test
    void daemonNotRunningPrintsHint() {
        Path bogusSocket = tempDir.resolve("nonexistent.sock");
        assertThrows(DaemonClient.DaemonNotRunningException.class,
                () -> DaemonClient.connect(bogusSocket));
    }
}
