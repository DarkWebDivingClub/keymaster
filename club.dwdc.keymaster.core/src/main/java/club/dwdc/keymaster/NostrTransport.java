package club.dwdc.keymaster;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import nostr.crypto.schnorr.Schnorr;
import nostr.encryption.MessageCipher44;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Nostr transport layer for KeyMaster-Avatar communication.
 * Handles NIP-44 encrypted kind-27235 events over a Nostr relay.
 */
public class NostrTransport {
    private static final Logger log = LoggerFactory.getLogger(NostrTransport.class);
    private static final int PROTOCOL_KIND = 27235;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    static {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private final byte[] privKey;
    private final byte[] pubKey;
    private final String pubKeyHex;

    private NostrRelayClient relayClient;
    private String sessionEventId;

    private final ConcurrentHashMap<String, CompletableFuture<JsonObject>> pendingResponses =
            new ConcurrentHashMap<>();

    /**
     * @param privKey 32-byte Schnorr private key (vault-derived)
     * @param pubKey  32-byte Schnorr public key (vault-derived)
     */
    public NostrTransport(byte[] privKey, byte[] pubKey) {
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.pubKeyHex = NostrUtil.bytesToHex(pubKey);
    }

    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /**
     * Connect to the Nostr relay and subscribe to events addressed to our pubkey.
     */
    public void connect(String relayUrl) throws InterruptedException {
        this.relayClient = new NostrRelayClient(relayUrl, new NostrRelayClient.Listener() {
            @Override
            public void onConnected() {
                log.info("Connected to relay: {}", relayUrl);
            }

            @Override
            public void onMessage(String text) {
                handleRelayMessage(text);
            }

            @Override
            public void onError(String error) {
                log.error("Relay error: {}", error);
            }

            @Override
            public void onClosed() {
                log.info("Disconnected from relay");
            }
        });

        relayClient.connect();
        Thread.sleep(500);

        String subId = "km-" + System.currentTimeMillis();
        String subMsg = String.format(
                "[\"REQ\",\"%s\",{\"kinds\":[%d],\"#p\":[\"%s\"],\"since\":%d}]",
                subId, PROTOCOL_KIND, pubKeyHex, System.currentTimeMillis() / 1000 - 1);
        relayClient.send(subMsg);
        log.info("Subscribed to kind {} events for {}", PROTOCOL_KIND, pubKeyHex);
        Thread.sleep(300);
    }

    /**
     * Send an attach request to the Avatar identified by its public key.
     *
     * @param avatarPubKeyHex Avatar's Schnorr public key (hex)
     * @return session event ID on success
     */
    public String sendAttach(String avatarPubKeyHex) throws Exception {
        JsonObject params = new JsonObject();
        params.add("services", new JsonArray());

        String eventId = sendRequest("attach", params, avatarPubKeyHex, null);
        this.sessionEventId = eventId;

        JsonObject response = waitForResponse(eventId, 15);
        if (response != null && response.has("result")) {
            log.info("Attach successful. Session: {}", eventId);
            return eventId;
        } else {
            String error = response != null && response.has("error")
                    ? response.get("error").getAsString() : "no response";
            throw new RuntimeException("Attach failed: " + error);
        }
    }

    /**
     * Send a detach request to end the current session.
     */
    public void sendDetach(String avatarPubKeyHex) throws Exception {
        if (sessionEventId == null) {
            log.warn("No active session to detach");
            return;
        }

        String eventId = sendRequest("detach", null, avatarPubKeyHex, sessionEventId);
        JsonObject response = waitForResponse(eventId, 10);
        if (response != null && response.has("result")) {
            log.info("Detach successful");
        }
        sessionEventId = null;
    }

    public void close() {
        if (relayClient != null) {
            relayClient.close();
        }
    }

    // ==================== Internal: send / receive ====================

    String sendRequest(String method, JsonObject params, String recipientPubKeyHex,
                       String refSessionEventId) throws Exception {
        JsonObject request = new JsonObject();
        request.addProperty("method", method);
        JsonArray paramsArr = new JsonArray();
        if (params != null) paramsArr.add(params);
        request.add("params", paramsArr);

        String plaintext = GSON.toJson(request);
        String encrypted = encrypt(plaintext, privKey, NostrUtil.hexToBytes(recipientPubKeyHex));

        long createdAt = System.currentTimeMillis() / 1000;
        JsonArray tags = new JsonArray();
        JsonArray pTag = new JsonArray();
        pTag.add("p");
        pTag.add(recipientPubKeyHex);
        tags.add(pTag);

        if (refSessionEventId != null) {
            JsonArray eTag = new JsonArray();
            eTag.add("e");
            eTag.add(refSessionEventId);
            eTag.add("");
            eTag.add("session");
            tags.add(eTag);
        }

        String eventId = computeEventId(pubKeyHex, createdAt, PROTOCOL_KIND, tags, encrypted);
        String sig = signEvent(eventId, privKey);

        JsonObject event = new JsonObject();
        event.addProperty("id", eventId);
        event.addProperty("pubkey", pubKeyHex);
        event.addProperty("created_at", createdAt);
        event.addProperty("kind", PROTOCOL_KIND);
        event.add("tags", tags);
        event.addProperty("content", encrypted);
        event.addProperty("sig", sig);

        CompletableFuture<JsonObject> future = new CompletableFuture<>();
        pendingResponses.put(eventId, future);

        String msg = "[\"EVENT\"," + GSON.toJson(event) + "]";
        relayClient.send(msg);
        log.debug("Sent {} request (event: {})", method, eventId);

        return eventId;
    }

    private JsonObject waitForResponse(String eventId, int timeoutSecs) throws Exception {
        CompletableFuture<JsonObject> future = pendingResponses.get(eventId);
        if (future == null) return null;

        try {
            return future.get(timeoutSecs, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            log.warn("Timeout waiting for response to {}", eventId);
            pendingResponses.remove(eventId);
            return null;
        }
    }

    private void handleRelayMessage(String text) {
        try {
            JsonArray msg = JsonParser.parseString(text).getAsJsonArray();
            String type = msg.get(0).getAsString();

            if ("EVENT".equals(type)) {
                JsonObject event = msg.get(2).getAsJsonObject();
                handleIncomingEvent(event);
            }
        } catch (Exception e) {
            log.debug("Non-event relay message: {}", text);
        }
    }

    private void handleIncomingEvent(JsonObject event) {
        try {
            int kind = event.get("kind").getAsInt();
            if (kind != PROTOCOL_KIND) return;

            String senderPubKey = event.get("pubkey").getAsString();
            String content = event.get("content").getAsString();
            String eventId = event.get("id").getAsString();

            String plaintext;
            try {
                plaintext = decrypt(content, privKey, NostrUtil.hexToBytes(senderPubKey));
            } catch (Exception e) {
                log.debug("Could not decrypt event {} from {}", eventId, senderPubKey);
                return;
            }

            log.debug("Decrypted from {}: {}", senderPubKey, plaintext);
            JsonObject payload = JsonParser.parseString(plaintext).getAsJsonObject();

            if (payload.has("result") || payload.has("error")) {
                handleResponse(event, payload);
            }
        } catch (Exception e) {
            log.error("Error handling event: {}", e.getMessage());
        }
    }

    private void handleResponse(JsonObject event, JsonObject payload) {
        JsonArray tags = event.getAsJsonArray("tags");
        for (JsonElement tag : tags) {
            JsonArray tagArr = tag.getAsJsonArray();
            if (tagArr.size() >= 4
                    && "e".equals(tagArr.get(0).getAsString())
                    && "reply".equals(tagArr.get(3).getAsString())) {
                String replyTo = tagArr.get(1).getAsString();
                CompletableFuture<JsonObject> future = pendingResponses.remove(replyTo);
                if (future != null) {
                    future.complete(payload);
                    return;
                }
            }
        }
        log.debug("Response with no matching pending request");
    }

    // ==================== Crypto helpers ====================

    static String encrypt(String plaintext, byte[] senderPrivKey, byte[] recipientPubKey)
            throws Exception {
        MessageCipher44 cipher = new MessageCipher44(senderPrivKey, recipientPubKey);
        return cipher.encrypt(plaintext);
    }

    static String decrypt(String ciphertext, byte[] recipientPrivKey, byte[] senderPubKey)
            throws Exception {
        MessageCipher44 cipher = new MessageCipher44(recipientPrivKey, senderPubKey);
        return cipher.decrypt(ciphertext);
    }

    static String computeEventId(String pubkey, long createdAt, int kind,
                                 JsonArray tags, String content) throws Exception {
        String serialized = String.format("[0,\"%s\",%d,%d,%s,\"%s\"]",
                pubkey, createdAt, kind, GSON.toJson(tags), escapeJsonString(content));
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(serialized.getBytes(StandardCharsets.UTF_8));
        return NostrUtil.bytesToHex(hash);
    }

    static String signEvent(String eventIdHex, byte[] privKey) throws Exception {
        byte[] eventIdBytes = NostrUtil.hexToBytes(eventIdHex);
        byte[] sig = Schnorr.sign(eventIdBytes, privKey, NostrEventHelper.generateAuxRand());
        return NostrUtil.bytesToHex(sig);
    }

    static String escapeJsonString(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
