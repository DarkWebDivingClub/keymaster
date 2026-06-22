package club.dwdc.keymaster.cli;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Unix domain socket client for JSON-RPC communication with the KeyMaster daemon.
 */
class DaemonClient implements AutoCloseable {

    private final SocketChannel channel;
    private final OutputStream out;
    private final BufferedReader reader;

    private int nextId = 1;

    private DaemonClient(SocketChannel channel) {
        this.channel = channel;
        this.out = Channels.newOutputStream(channel);
        this.reader = new BufferedReader(
                new InputStreamReader(Channels.newInputStream(channel), StandardCharsets.UTF_8));
    }

    /**
     * Connect to the daemon at the given socket path.
     *
     * @throws DaemonNotRunningException if the connection is refused
     */
    static DaemonClient connect(Path socketPath) throws IOException {
        try {
            SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX);
            channel.connect(UnixDomainSocketAddress.of(socketPath));
            return new DaemonClient(channel);
        } catch (java.net.SocketException | java.nio.file.NoSuchFileException e) {
            throw new DaemonNotRunningException(socketPath);
        }
    }

    /**
     * Send a JSON-RPC request and return the parsed response.
     */
    JsonObject sendRequest(String method, JsonObject params) throws IOException {
        JsonObject request = new JsonObject();
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("id", String.valueOf(nextId++));
        request.addProperty("method", method);
        request.add("params", params != null ? params : new JsonObject());

        out.write(request.toString().getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();

        String line = reader.readLine();
        if (line == null) {
            throw new IOException("Daemon closed the connection unexpectedly");
        }
        return JsonParser.parseString(line).getAsJsonObject();
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    /**
     * Thrown when the daemon socket cannot be reached.
     */
    static class DaemonNotRunningException extends IOException {
        DaemonNotRunningException(Path socketPath) {
            super("Cannot connect to daemon at " + socketPath);
        }
    }
}
