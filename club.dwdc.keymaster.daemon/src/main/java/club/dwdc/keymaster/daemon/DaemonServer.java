package club.dwdc.keymaster.daemon;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Unix domain socket server for JSON-RPC communication.
 *
 * <p>Accepts connections on a Unix domain socket, reads line-delimited JSON-RPC 2.0
 * requests, dispatches them to a {@link RequestHandler}, and writes responses.
 */
public class DaemonServer {

    private static final Logger log = LoggerFactory.getLogger(DaemonServer.class);

    private final Path socketPath;
    private final RequestHandler handler;
    private volatile ServerSocketChannel serverChannel;
    private volatile Thread acceptThread;

    /**
     * Handler for dispatching JSON-RPC requests.
     */
    @FunctionalInterface
    public interface RequestHandler {
        JsonObject handle(String method, JsonObject params);
    }

    public DaemonServer(Path socketPath, RequestHandler handler) {
        this.socketPath = socketPath;
        this.handler = handler;
    }

    /**
     * Bind the socket and start accepting connections.
     */
    public void start() throws IOException {
        // Clean up stale socket file
        Files.deleteIfExists(socketPath);

        serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        serverChannel.bind(UnixDomainSocketAddress.of(socketPath));
        log.info("Listening on {}", socketPath);

        acceptThread = new Thread(this::acceptLoop, "daemon-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    /**
     * Stop the server: close the socket and clean up the socket file.
     */
    public void stop() {
        if (acceptThread != null) {
            acceptThread.interrupt();
        }
        if (serverChannel != null) {
            try {
                serverChannel.close();
            } catch (IOException e) {
                log.warn("Error closing server channel", e);
            }
        }
        try {
            Files.deleteIfExists(socketPath);
        } catch (IOException e) {
            log.warn("Error deleting socket file", e);
        }
    }

    private void acceptLoop() {
        try {
            while (serverChannel.isOpen()) {
                SocketChannel client = serverChannel.accept();
                Thread.startVirtualThread(() -> handleConnection(client));
            }
        } catch (IOException e) {
            if (serverChannel.isOpen()) {
                log.error("Accept loop error", e);
            }
            // else: expected on shutdown
        }
    }

    private void handleConnection(SocketChannel client) {
        try (client) {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(Channels.newInputStream(client), StandardCharsets.UTF_8));
            OutputStream out = Channels.newOutputStream(client);

            String line;
            while ((line = reader.readLine()) != null) {
                String response = processRequest(line);
                out.write(response.getBytes(StandardCharsets.UTF_8));
                out.write('\n');
                out.flush();
            }
        } catch (IOException e) {
            log.debug("Connection closed: {}", e.getMessage());
        }
    }

    private String processRequest(String requestLine) {
        try {
            JsonObject request = JsonParser.parseString(requestLine).getAsJsonObject();
            String id = request.has("id") ? request.get("id").getAsString() : null;
            String method = request.get("method").getAsString();
            JsonObject params = request.has("params") ? request.getAsJsonObject("params") : new JsonObject();

            JsonObject result = handler.handle(method, params);

            JsonObject response = new JsonObject();
            response.addProperty("jsonrpc", "2.0");
            if (id != null) {
                response.addProperty("id", id);
            }

            if (result.has("error")) {
                JsonObject error = new JsonObject();
                error.addProperty("code", -32000);
                error.addProperty("message", result.get("error").getAsString());
                response.add("error", error);
            } else {
                response.add("result", result);
            }

            return response.toString();
        } catch (Exception e) {
            log.error("Error processing request: {}", requestLine, e);
            JsonObject response = new JsonObject();
            response.addProperty("jsonrpc", "2.0");
            JsonObject error = new JsonObject();
            error.addProperty("code", -32600);
            error.addProperty("message", e.getMessage());
            response.add("error", error);
            return response.toString();
        }
    }
}
