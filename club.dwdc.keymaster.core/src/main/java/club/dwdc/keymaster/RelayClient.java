package club.dwdc.keymaster;

/**
 * Transport-agnostic relay client for sending and receiving Nostr messages.
 * Implementations provide the actual transport (WebSocket, RFCOMM, etc.).
 */
public interface RelayClient {

    interface Listener {
        void onConnected();
        void onMessage(String text);
        void onError(String error);
        void onClosed();
    }

    void setListener(Listener listener);

    void connect() throws Exception;

    void send(String message);

    void close();
}
