package club.dwdc.keymaster;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Simple Nostr relay WebSocket client using OkHttp.
 */
public class NostrRelayClient {
    private static final Logger log = LoggerFactory.getLogger(NostrRelayClient.class);

    private final String url;
    private final Listener listener;
    private final OkHttpClient httpClient;
    private WebSocket webSocket;
    private final CountDownLatch connectLatch = new CountDownLatch(1);

    public interface Listener {
        void onConnected();
        void onMessage(String text);
        void onError(String error);
        void onClosed();
    }

    public NostrRelayClient(String url, Listener listener) {
        this.url = url;
        this.listener = listener;
        this.httpClient = new OkHttpClient.Builder()
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .pingInterval(30, TimeUnit.SECONDS)
                .build();
    }

    public void connect() throws InterruptedException {
        Request request = new Request.Builder()
                .url(url)
                .build();

        webSocket = httpClient.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(WebSocket ws, Response response) {
                log.debug("WebSocket connected to {}", url);
                connectLatch.countDown();
                listener.onConnected();
            }

            @Override
            public void onMessage(WebSocket ws, String text) {
                log.debug("Received: {}", text);
                listener.onMessage(text);
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, Response response) {
                log.error("WebSocket failure: {}", t.getMessage());
                listener.onError(t.getMessage());
                connectLatch.countDown();
            }

            @Override
            public void onClosed(WebSocket ws, int code, String reason) {
                log.debug("WebSocket closed: {} {}", code, reason);
                listener.onClosed();
            }
        });

        if (!connectLatch.await(10, TimeUnit.SECONDS)) {
            throw new RuntimeException("Connection to relay timed out: " + url);
        }
    }

    public void send(String message) {
        log.debug("Sending: {}", message);
        if (webSocket != null) {
            webSocket.send(message);
        }
    }

    public void close() {
        if (webSocket != null) {
            webSocket.close(1000, "bye");
        }
        httpClient.dispatcher().executorService().shutdown();
    }
}
