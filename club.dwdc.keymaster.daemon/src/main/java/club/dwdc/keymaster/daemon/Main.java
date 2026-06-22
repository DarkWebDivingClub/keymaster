package club.dwdc.keymaster.daemon;

import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keyvault.desktop.FileSeedStore;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/**
 * KeyMaster daemon entry point — {@code km-daemon}.
 *
 * <p>Starts a Unix domain socket server for JSON-RPC communication.
 * The daemon manages identity storage and avatar attach sessions.
 *
 * <h3>Options</h3>
 * <ul>
 *   <li>{@code --socket <path>} — Unix socket path
 *       (default: {@code $KM_SOCKET} or {@code $XDG_RUNTIME_DIR/keymaster.sock})</li>
 * </ul>
 */
public class Main {

    public static void main(String[] args) throws Exception {
        Path socketPath = resolveSocketPath(args);
        Path configDir = defaultConfigDir();

        FileSeedStore seedStore = new FileSeedStore();
        FileIdentityStore identityStore = new FileIdentityStore();
        DaemonController controller = new DaemonController(seedStore, identityStore, configDir);
        DaemonServer server = new DaemonServer(socketPath, controller);

        server.start();
        System.out.println("Listening on " + socketPath);

        CountDownLatch latch = new CountDownLatch(1);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down...");
            controller.shutdown();
            server.stop();
            latch.countDown();
        }));

        latch.await();
    }

    static Path resolveSocketPath(String[] args) {
        // Check --socket argument
        for (int i = 0; i < args.length - 1; i++) {
            if ("--socket".equals(args[i])) {
                return Path.of(args[i + 1]);
            }
        }

        // Check KM_SOCKET env
        String envSocket = System.getenv("KM_SOCKET");
        if (envSocket != null && !envSocket.isEmpty()) {
            return Path.of(envSocket);
        }

        // Default: $XDG_RUNTIME_DIR/keymaster.sock
        String xdgRuntime = System.getenv("XDG_RUNTIME_DIR");
        if (xdgRuntime != null && !xdgRuntime.isEmpty()) {
            return Path.of(xdgRuntime, "keymaster.sock");
        }

        // Fallback
        return Path.of(System.getProperty("java.io.tmpdir"), "keymaster.sock");
    }

    private static Path defaultConfigDir() {
        String kmHome = System.getenv("KM_HOME");
        if (kmHome != null && !kmHome.isEmpty()) {
            return Path.of(kmHome);
        }
        return Path.of(System.getProperty("user.home"), ".config", "keymaster");
    }
}
