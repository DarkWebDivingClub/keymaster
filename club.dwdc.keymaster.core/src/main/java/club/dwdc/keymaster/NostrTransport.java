package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.crypto.schnorr.Schnorr;
import nostr.encryption.MessageCipher44;
import nostr.util.NostrUtil;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/**
 * Nostr transport layer for KeyMaster-Avatar communication.
 * Handles NIP-44 encrypted kind-27235 events over a Nostr relay.
 *
 * <p>Service channels are derived deterministically from exchanged xpubs —
 * no service.spawn round-trip is needed.</p>
 */
public class NostrTransport {
    private static final Logger log = LoggerFactory.getLogger(NostrTransport.class);
    private static final int PROTOCOL_KIND = 27235;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");

    /** Relay connection state visible to the UI layer. */
    public enum ConnectionState { CONNECTED, RETRYING, DISCONNECTED }

    static {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private final TransportSigner signer;
    private final String pubKeyHex;

    private NostrRelayClient relayClient;
    private String attachEventId;

    /** Vault and realm base path for deriving service channel keys. */
    private KeyVault vault;
    private int[] realmBasePath;
    private int realmIndex;

    private final ConcurrentHashMap<String, CompletableFuture<JsonObject>> pendingResponses =
            new ConcurrentHashMap<>();

    // Service channel tracking: keyed by avatar service pubkey hex
    private final ConcurrentHashMap<String, ServiceChannelInfo> serviceChannels =
            new ConcurrentHashMap<>();

    /** Avatar login npub (hex) — set during attach for p tag markers on responses. */
    private String avatarLoginPubkey;

    private ServiceRequestHandler serviceRequestHandler;
    private Consumer<ConnectionState> connectionStateListener;

    /**
     * Callback for handling incoming service requests (e.g. request_identities).
     */
    public interface ServiceRequestHandler {
        JsonObject handleServiceRequest(String serviceType, String method, JsonArray params);
    }

    /**
     * Tracks a service channel between KM and Avatar.
     */
    static class ServiceChannelInfo {
        final String serviceType;
        final int[] vaultPath;
        final byte[] kmServicePubKey;
        final String kmServicePubKeyHex;
        final String avatarServicePubKeyHex;

        ServiceChannelInfo(String serviceType, int[] vaultPath, byte[] pubKey,
                           String avatarServicePubKeyHex) {
            this.serviceType = serviceType;
            this.vaultPath = vaultPath;
            this.kmServicePubKey = pubKey;
            this.kmServicePubKeyHex = NostrUtil.bytesToHex(pubKey);
            this.avatarServicePubKeyHex = avatarServicePubKeyHex;
        }
    }

    /**
     * @param signer vault-backed transport signer for pubkey, signing, and ECDH
     */
    public NostrTransport(TransportSigner signer) {
        this.signer = signer;
        this.pubKeyHex = signer.getPubkey();
    }

    public String getPubKeyHex() {
        return pubKeyHex;
    }

    public void setServiceRequestHandler(ServiceRequestHandler handler) {
        this.serviceRequestHandler = handler;
    }

    public void setConnectionStateListener(Consumer<ConnectionState> listener) {
        this.connectionStateListener = listener;
    }

    private void fireConnectionState(ConnectionState state) {
        if (connectionStateListener != null) {
            connectionStateListener.accept(state);
        }
    }

    /**
     * Set the vault and realm base path for deterministic service channel derivation.
     * Service channel keys are derived at: realmBasePath / realmIndex / protocolIdx / seq
     */
    public void setRealmVault(KeyVault vault, int[] realmBasePath, int realmIndex) {
        this.vault = vault;
        this.realmBasePath = realmBasePath;
        this.realmIndex = realmIndex;
    }

    /**
     * Connect to the Nostr relay and subscribe to events addressed to our pubkey.
     */
    public void connect(String relayUrl) throws InterruptedException {
        this.relayClient = new NostrRelayClient(relayUrl, new NostrRelayClient.Listener() {
            @Override
            public void onConnected() {
                log.info("Connected to relay: {}", relayUrl);
                fireConnectionState(ConnectionState.CONNECTED);
            }

            @Override
            public void onMessage(String text) {
                handleRelayMessage(text);
            }

            @Override
            public void onError(String error) {
                log.error("Relay error: {}", error);
                fireConnectionState(ConnectionState.RETRYING);
            }

            @Override
            public void onClosed() {
                log.info("Disconnected from relay");
                fireConnectionState(ConnectionState.DISCONNECTED);
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
     * Send an attach request to the Avatar.
     *
     * @param avatarLoginXpub Avatar's BIP-32 login xpub (Base58Check)
     * @param services        list of service identifiers to request
     * @param realmXpub       our realm xpub to share with the Avatar
     * @param identityPubkey  the identity pubkey (64-char hex Nostr pubkey)
     * @param connectorSig    64-byte Schnorr signature of the connector hash, or {@code null}
     * @return attach event ID on success
     */
    public String sendAttach(String avatarLoginXpub, List<String> services,
                             String realmXpub, String identityPubkey,
                             byte[] connectorSig) throws Exception {
        // Derive the avatar's login pubkey from the xpub for event addressing
        String avatarPubKeyHex = xpubToPubkey(avatarLoginXpub);

        JsonObject params = new JsonObject();
        JsonArray servicesArr = new JsonArray();
        if (services != null) {
            services.forEach(servicesArr::add);
        }
        params.add("services", servicesArr);

        // Add connector with realm_xpub and identity
        JsonObject connector = new JsonObject();
        connector.addProperty("realm_xpub", realmXpub);
        connector.addProperty("login_xpub", avatarLoginXpub);
        if (identityPubkey != null) {
            connector.addProperty("identity_npub", identityPubkey);
        }
        params.add("connector", connector);

        // Attach pre-computed connector signature
        if (connectorSig != null) {
            params.addProperty("connector_sig", NostrUtil.bytesToHex(connectorSig));
        }

        // Store avatar login npub for p tag markers on responses
        this.avatarLoginPubkey = avatarPubKeyHex;

        String eventId = sendRequest("attach", params, avatarPubKeyHex, null);
        this.attachEventId = eventId;

        JsonObject response = waitForResponse(eventId, 15);
        if (response != null && response.has("result")) {
            log.info("Attach successful. Session: {}", eventId);

            // Derive service channels from xpubs (zero extra round-trips)
            deriveServiceChannels(avatarLoginXpub, services);

            return eventId;
        } else {
            String error = response != null && response.has("error")
                    ? response.get("error").getAsString() : "no response";
            throw new RuntimeException("Attach failed: " + error);
        }
    }

    /**
     * Derive service channel keypairs from the exchanged xpubs.
     * Both sides compute the same channel pubkeys independently.
     */
    private void deriveServiceChannels(String avatarLoginXpub, List<String> services) {
        if (vault == null || realmBasePath == null) {
            log.warn("No realm vault/path set — cannot derive service channels");
            return;
        }
        if (services == null) return;

        for (String serviceType : services) {
            try {
                int protocolIdx = Bip32KeyDerivator.mangle(serviceType);
                int seq = 0;

                // Build extended vault path: realmBasePath / realmIndex / protocolIdx / seq
                int[] svcPath = extendPath(realmBasePath, realmIndex, protocolIdx, seq);

                // Derive our (KM) service channel public key from vault
                VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, svcPath);
                if (!pubResult.isOk()) {
                    log.error("Failed to derive service pubkey for {}: status {}",
                            serviceType, pubResult.status());
                    continue;
                }
                // Compressed (33 bytes) → x-only (32 bytes)
                byte[] compressed = pubResult.data();
                byte[] kmSvcPubKey = java.util.Arrays.copyOfRange(compressed, 1, 33);
                String kmSvcPubKeyHex = NostrUtil.bytesToHex(kmSvcPubKey);

                // Derive avatar's service channel pubkey from their login xpub
                String avatarSvcPubKeyHex = deriveServicePubkeyFromXpub(
                        avatarLoginXpub, protocolIdx, seq);

                ServiceChannelInfo channel = new ServiceChannelInfo(
                        serviceType, svcPath, kmSvcPubKey, avatarSvcPubKeyHex);
                serviceChannels.put(avatarSvcPubKeyHex, channel);

                // Subscribe to events addressed to our service pubkey
                String svcSubId = "svc-" + serviceType + "-" + System.currentTimeMillis();
                String subMsg = String.format(
                        "[\"REQ\",\"%s\",{\"kinds\":[%d],\"#p\":[\"%s\"],\"since\":%d}]",
                        svcSubId, PROTOCOL_KIND, kmSvcPubKeyHex,
                        System.currentTimeMillis() / 1000 - 1);
                relayClient.send(subMsg);

                log.info("Service channel derived: type={}, km_svc_pk={}, avatar_svc_pk={}",
                        serviceType, kmSvcPubKeyHex, avatarSvcPubKeyHex);

            } catch (Exception e) {
                log.error("Error deriving service channel for {}: {}", serviceType, e.getMessage(), e);
            }
        }
    }

    /**
     * Extend a base path with additional non-hardened child indices.
     */
    private static int[] extendPath(int[] basePath, int... children) {
        int[] result = new int[basePath.length + children.length];
        System.arraycopy(basePath, 0, result, 0, basePath.length);
        System.arraycopy(children, 0, result, basePath.length, children.length);
        return result;
    }

    /**
     * Derive a service pubkey from an xpub string using BIP-32 public-only derivation.
     * Path: xpub / protocolIndex / seq
     *
     * @return x-only (Schnorr) pubkey hex
     */
    static String deriveServicePubkeyFromXpub(String xpubStr, int protocolIndex, int seq) {
        DeterministicKey xpubKey = DeterministicKey.deserializeB58(xpubStr, BitcoinNetwork.MAINNET);
        DeterministicKey child1 = org.bitcoinj.crypto.HDKeyDerivation.deriveChildKey(
                xpubKey, new ChildNumber(protocolIndex));
        DeterministicKey child2 = org.bitcoinj.crypto.HDKeyDerivation.deriveChildKey(
                child1, new ChildNumber(seq));
        // Compressed pubkey (33 bytes) -> x-only (32 bytes)
        byte[] compressed = child2.getPubKey();
        byte[] xOnly = new byte[32];
        System.arraycopy(compressed, 1, xOnly, 0, 32);
        return NostrUtil.bytesToHex(xOnly);
    }

    /**
     * Extract the x-only (Schnorr) pubkey from a BIP-32 xpub string.
     */
    static String xpubToPubkey(String xpubStr) {
        DeterministicKey key = DeterministicKey.deserializeB58(xpubStr, BitcoinNetwork.MAINNET);
        byte[] compressed = key.getPubKey();
        byte[] xOnly = new byte[32];
        System.arraycopy(compressed, 1, xOnly, 0, 32);
        return NostrUtil.bytesToHex(xOnly);
    }

    /**
     * Send a detach request to end the current session.
     */
    public void sendDetach(String avatarLoginXpub) throws Exception {
        if (attachEventId == null) {
            log.warn("No active session to detach");
            return;
        }

        String avatarPubKeyHex = xpubToPubkey(avatarLoginXpub);
        String eventId = sendRequest("detach", null, avatarPubKeyHex, attachEventId);
        JsonObject response = waitForResponse(eventId, 10);
        if (response != null && response.has("result")) {
            log.info("Detach successful");
        }
        attachEventId = null;
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
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("method", method);
        JsonArray paramsArr = new JsonArray();
        if (params != null) paramsArr.add(params);
        request.add("params", paramsArr);

        String plaintext = GSON.toJson(request);
        String encrypted = encryptViaSigner(plaintext, NostrUtil.hexToBytes(recipientPubKeyHex));

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
        String sig = NostrUtil.bytesToHex(signer.sign(NostrUtil.hexToBytes(eventId)));

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

            // Try root key decryption first
            String plaintext = null;
            ServiceChannelInfo matchedChannel = null;

            try {
                plaintext = decryptViaSigner(content, NostrUtil.hexToBytes(senderPubKey));
            } catch (Exception e) {
                // Try service channel keys via vault ECDH
                for (ServiceChannelInfo channel : serviceChannels.values()) {
                    try {
                        plaintext = decryptViaVault(content,
                                NostrUtil.hexToBytes(senderPubKey), channel.vaultPath);
                        matchedChannel = channel;
                        break;
                    } catch (Exception e2) {
                        // try next channel
                    }
                }
            }

            if (plaintext == null) {
                log.debug("Could not decrypt event {} from {}", eventId, senderPubKey);
                return;
            }

            log.debug("Decrypted from {}: {}", senderPubKey, plaintext);
            JsonObject payload = JsonParser.parseString(plaintext).getAsJsonObject();

            if (payload.has("method")) {
                // Incoming request — only service channel requests expected
                if (matchedChannel != null) {
                    handleServiceChannelRequest(event, matchedChannel, payload);
                } else {
                    log.warn("Root request received but service.spawn no longer supported: {}",
                            payload.get("method").getAsString());
                }
            } else if (payload.has("result") || payload.has("error")) {
                handleResponse(event, payload);
            }
        } catch (Exception e) {
            log.error("Error handling event: {}", e.getMessage(), e);
        }
    }

    // ==================== Request handling ====================

    private void handleServiceChannelRequest(JsonObject event, ServiceChannelInfo channel,
                                             JsonObject payload) {
        String rawMethod = payload.get("method").getAsString();
        // The method from the payload may be prefixed with the service type
        // (e.g. "ssh.request_identities"). Strip the prefix so the handler
        // receives just the bare method name (e.g. "request_identities").
        String method = rawMethod;
        String prefix = channel.serviceType + ".";
        if (rawMethod.startsWith(prefix)) {
            method = rawMethod.substring(prefix.length());
        }

        JsonArray params;
        if (payload.has("params")) {
            var paramsEl = payload.get("params");
            if (paramsEl.isJsonArray()) {
                params = paramsEl.getAsJsonArray();
            } else {
                // Wrap object params in an array for uniform handling
                params = new JsonArray();
                params.add(paramsEl);
            }
        } else {
            params = new JsonArray();
        }

        log.info("Service request: {}.{}", channel.serviceType, method);

        JsonObject response;
        if (serviceRequestHandler != null) {
            try {
                response = serviceRequestHandler.handleServiceRequest(
                        channel.serviceType, method, params);
            } catch (Exception e) {
                log.error("Service request handler error: {}", e.getMessage(), e);
                response = new JsonObject();
                response.addProperty("error", e.getMessage());
            }
        } else {
            response = new JsonObject();
            response.addProperty("error", "no service handler registered");
        }

        // Wrap handler response as JSON-RPC 2.0
        JsonObject rpcResponse = new JsonObject();
        rpcResponse.addProperty("jsonrpc", "2.0");
        if (payload.has("id")) {
            rpcResponse.add("id", payload.get("id"));
        }
        if (response.has("error")) {
            // Wrap as a proper JSON-RPC 2.0 error object with code and message
            JsonObject errorObj = new JsonObject();
            errorObj.addProperty("code", -32603); // internal error
            errorObj.addProperty("message", response.get("error").getAsString());
            rpcResponse.add("error", errorObj);
        } else if (response.has("result")) {
            // Handler already wrapped its data in a "result" field — unwrap to avoid
            // double-nesting (result.result.identities vs result.identities)
            rpcResponse.add("result", response.get("result"));
        } else {
            rpcResponse.add("result", response);
        }

        String replyToEventId = event.get("id").getAsString();
        sendResponseEvent(replyToEventId, channel.avatarServicePubKeyHex, rpcResponse,
                channel.vaultPath, channel.kmServicePubKeyHex);
    }

    // ==================== Response handling ====================

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

    // ==================== Event sending ====================

    private void sendResponseEvent(String replyToEventId, String recipientPubKeyHex,
                                   JsonObject response, int[] vaultPath,
                                   String signingPubKeyHex) {
        try {
            String plaintext = GSON.toJson(response);
            String encrypted = encryptViaVault(plaintext,
                    NostrUtil.hexToBytes(recipientPubKeyHex), vaultPath);

            long createdAt = System.currentTimeMillis() / 1000;
            JsonArray tags = new JsonArray();

            JsonArray pTag = new JsonArray();
            pTag.add("p");
            pTag.add(recipientPubKeyHex);
            tags.add(pTag);

            // Add "login" marker p tag for unified subscription routing
            if (avatarLoginPubkey != null) {
                JsonArray loginPTag = new JsonArray();
                loginPTag.add("p");
                loginPTag.add(avatarLoginPubkey);
                loginPTag.add("");
                loginPTag.add("login");
                tags.add(loginPTag);
            }

            JsonArray eTag = new JsonArray();
            eTag.add("e");
            eTag.add(replyToEventId);
            eTag.add("");
            eTag.add("reply");
            tags.add(eTag);

            String eventId = computeEventId(signingPubKeyHex, createdAt, PROTOCOL_KIND,
                    tags, encrypted);
            String sig = signViaVault(eventId, vaultPath);

            JsonObject event = new JsonObject();
            event.addProperty("id", eventId);
            event.addProperty("pubkey", signingPubKeyHex);
            event.addProperty("created_at", createdAt);
            event.addProperty("kind", PROTOCOL_KIND);
            event.add("tags", tags);
            event.addProperty("content", encrypted);
            event.addProperty("sig", sig);

            String msg = "[\"EVENT\"," + GSON.toJson(event) + "]";
            relayClient.send(msg);
            log.debug("Sent response event {} (reply to {})", eventId, replyToEventId);
        } catch (Exception e) {
            log.error("Failed to send response event: {}", e.getMessage(), e);
        }
    }

    // ==================== Crypto helpers ====================

    /**
     * Encrypt using the transport signer's ECDH key agreement (vault-backed).
     */
    private String encryptViaSigner(String plaintext, byte[] recipientPubKey) throws Exception {
        byte[] sharedX = signer.ecdh(recipientPubKey);
        byte[] convKey = deriveNip44ConversationKey(sharedX);
        byte[] nonce = NostrUtil.createRandomByteArray(32);
        return EncryptedPayloads.encrypt(plaintext, convKey, nonce);
    }

    /**
     * Decrypt using the transport signer's ECDH key agreement (vault-backed).
     */
    private String decryptViaSigner(String ciphertext, byte[] senderPubKey) throws Exception {
        byte[] sharedX = signer.ecdh(senderPubKey);
        byte[] convKey = deriveNip44ConversationKey(sharedX);
        return EncryptedPayloads.decrypt(ciphertext, convKey);
    }

    /**
     * NIP-44 conversation key: HKDF-Extract with salt "nip44-v2" over the
     * raw ECDH shared x-coordinate.
     */
    static byte[] deriveNip44ConversationKey(byte[] sharedX) {
        try {
            byte[] salt = "nip44-v2".getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(sharedX);
        } catch (Exception e) {
            throw new IllegalStateException("NIP-44 conversation key derivation failed", e);
        }
    }

    /**
     * Encrypt using vault-backed ECDH key agreement (service channel keys).
     */
    private String encryptViaVault(String plaintext, byte[] recipientPubKey, int[] vaultPath)
            throws Exception {
        VaultResult ecdhResult = vault.execute(KeyVault.FN_KEY_AGREEMENT, recipientPubKey, vaultPath);
        if (!ecdhResult.isOk()) {
            throw new RuntimeException("Vault ECDH failed: status " + ecdhResult.status());
        }
        byte[] convKey = deriveNip44ConversationKey(ecdhResult.data());
        byte[] nonce = NostrUtil.createRandomByteArray(32);
        return EncryptedPayloads.encrypt(plaintext, convKey, nonce);
    }

    /**
     * Decrypt using vault-backed ECDH key agreement (service channel keys).
     */
    private String decryptViaVault(String ciphertext, byte[] senderPubKey, int[] vaultPath)
            throws Exception {
        VaultResult ecdhResult = vault.execute(KeyVault.FN_KEY_AGREEMENT, senderPubKey, vaultPath);
        if (!ecdhResult.isOk()) {
            throw new RuntimeException("Vault ECDH failed: status " + ecdhResult.status());
        }
        byte[] convKey = deriveNip44ConversationKey(ecdhResult.data());
        return EncryptedPayloads.decrypt(ciphertext, convKey);
    }

    /**
     * Sign an event using vault-backed Schnorr signing (service channel keys).
     */
    private String signViaVault(String eventIdHex, int[] vaultPath) throws Exception {
        byte[] eventIdBytes = NostrUtil.hexToBytes(eventIdHex);
        VaultResult sigResult = vault.execute(KeyVault.FN_SIGN, eventIdBytes, vaultPath);
        if (!sigResult.isOk()) {
            throw new RuntimeException("Vault sign failed: status " + sigResult.status());
        }
        return NostrUtil.bytesToHex(sigResult.data());
    }

    /** Encrypt with raw private key — used for service channel crypto. */
    static String encrypt(String plaintext, byte[] senderPrivKey, byte[] recipientPubKey)
            throws Exception {
        MessageCipher44 cipher = new MessageCipher44(senderPrivKey, recipientPubKey);
        return cipher.encrypt(plaintext);
    }

    /** Decrypt with raw private key — used for service channel crypto. */
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

    /**
     * Canonical JSON: sort object keys lexicographically, compact output.
     * Produces deterministic byte-for-byte output for Schnorr signing.
     */
    static String canonicalizeJson(JsonObject obj) {
        TreeMap<String, String> sorted = new TreeMap<>();
        for (var entry : obj.entrySet()) {
            JsonElement val = entry.getValue();
            if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                sorted.put(entry.getKey(), "\"" + escapeJsonString(val.getAsString()) + "\"");
            } else {
                sorted.put(entry.getKey(), GSON.toJson(val));
            }
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : sorted.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJsonString(entry.getKey())).append("\":")
              .append(entry.getValue());
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Compute a BIP-340 (x-only) Schnorr public key from a 32-byte private key.
     */
    static byte[] computeSchnorrPubKey(byte[] privKey) {
        BigInteger d = new BigInteger(1, privKey);
        ECPoint point = SECP256K1.getG().multiply(d).normalize();
        return point.getAffineXCoord().getEncoded();
    }
}
