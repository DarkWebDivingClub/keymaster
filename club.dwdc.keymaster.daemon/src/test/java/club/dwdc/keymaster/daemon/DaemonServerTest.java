package club.dwdc.keymaster.daemon;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DaemonServerTest {

    @TempDir
    Path tempDir;

    @Test
    void startAndHandleRequest() throws Exception {
        Path socket = tempDir.resolve("test.sock");

        DaemonServer server = new DaemonServer(socket, (method, params) -> {
            JsonObject result = new JsonObject();
            result.addProperty("echo", method);
            return result;
        });

        server.start();
        assertTrue(Files.exists(socket));

        try {
            // Connect and send a JSON-RPC request
            String response = sendRequest(socket,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"test.echo\",\"params\":{}}");

            JsonObject json = JsonParser.parseString(response).getAsJsonObject();
            assertEquals("2.0", json.get("jsonrpc").getAsString());
            assertEquals("1", json.get("id").getAsString());
            assertTrue(json.has("result"));
            assertEquals("test.echo", json.getAsJsonObject("result").get("echo").getAsString());
        } finally {
            server.stop();
        }
    }

    @Test
    void stopCleansUpSocketFile() throws Exception {
        Path socket = tempDir.resolve("cleanup.sock");

        DaemonServer server = new DaemonServer(socket, (method, params) -> new JsonObject());
        server.start();
        assertTrue(Files.exists(socket));

        server.stop();
        assertFalse(Files.exists(socket));
    }

    @Test
    void errorResponseOnHandlerError() throws Exception {
        Path socket = tempDir.resolve("error.sock");

        DaemonServer server = new DaemonServer(socket, (method, params) -> {
            JsonObject result = new JsonObject();
            result.addProperty("error", "something went wrong");
            return result;
        });

        server.start();
        try {
            String response = sendRequest(socket,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"2\",\"method\":\"fail\",\"params\":{}}");

            JsonObject json = JsonParser.parseString(response).getAsJsonObject();
            assertTrue(json.has("error"));
            assertEquals("something went wrong",
                    json.getAsJsonObject("error").get("message").getAsString());
        } finally {
            server.stop();
        }
    }

    private String sendRequest(Path socket, String request) throws Exception {
        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(UnixDomainSocketAddress.of(socket));

            OutputStream out = Channels.newOutputStream(channel);
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(Channels.newInputStream(channel), StandardCharsets.UTF_8));
            return reader.readLine();
        }
    }
}
