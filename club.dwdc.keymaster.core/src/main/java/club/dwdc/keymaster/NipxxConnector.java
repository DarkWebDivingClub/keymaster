package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * NIP-xx transport connector — implements the KeyMaster-Avatar attach/detach
 * handshake over a Nostr relay using NIP-44 encrypted kind-27235 events.
 *
 * <p>Uses a vault-backed realm key for deterministic service channel derivation.
 * No private key ever enters this class — signing and ECDH are delegated to
 * a {@link TransportSigner} (identity key) or routed through the vault
 * (service channel keys).
 */
public class NipxxConnector implements Connector {
    private static final Logger log = LoggerFactory.getLogger(NipxxConnector.class);

    private final Realm realm;

    private KeyVault vault;
    private int[] realmBasePath;
    private int realmIndex;
    private String realmXpub;

    private NostrTransport transport;
    private String avatarLoginXpub;
    private final Map<String, ServiceChannel> channels = new HashMap<>();
    private Consumer<NostrTransport.ConnectionState> connectionStateListener;

    /**
     * @param realm realm containing active service handlers
     */
    public NipxxConnector(Realm realm) {
        this.realm = realm;

        // Build service channels from realm handlers (realm-based channels
        // resolve handlers lazily, so this is safe even if handlers change later)
        Gson serviceGson = ServiceChannel.createGson();
        for (int coinType : realm.getHandlerCoinTypes()) {
            String serviceType = coinTypeToServiceType(coinType);
            if (serviceType != null) {
                channels.put(serviceType, new ServiceChannel(realm, coinType, serviceGson));
            }
        }
    }

    /**
     * Inject the vault, realm base path, realm index, and pre-computed xpub
     * for deterministic service channel derivation.
     * Must be called before {@link #connect}.
     */
    public void setRealmVault(KeyVault vault, int[] realmBasePath, int realmIndex,
                              String realmXpub) {
        this.vault = vault;
        this.realmBasePath = realmBasePath;
        this.realmIndex = realmIndex;
        this.realmXpub = realmXpub;
    }

    public void setConnectionStateListener(Consumer<NostrTransport.ConnectionState> listener) {
        this.connectionStateListener = listener;
    }

    @Override
    public String connect(AvatarDescriptor avatar, TransportSigner signer) throws Exception {
        if (this.vault == null || this.realmBasePath == null) {
            throw new IllegalStateException(
                    "realm vault must be set before connect()");
        }

        // Transport uses the identity key directly — stable across reconnects
        this.transport = new NostrTransport(signer);
        transport.setRealmVault(this.vault, this.realmBasePath, this.realmIndex);
        transport.setServiceRequestHandler(this::handleServiceRequest);
        if (connectionStateListener != null) {
            transport.setConnectionStateListener(connectionStateListener);
        }
        transport.connect(avatar.relay());

        this.avatarLoginXpub = avatar.loginXpub();

        // Get identity pubkey and sign the connector hash
        String identityPubkey = signer.getPubkey();

        // Build the connector JSON for signing
        JsonObject connector = new JsonObject();
        connector.addProperty("realm_xpub", realmXpub);
        connector.addProperty("login_xpub", avatarLoginXpub);
        if (identityPubkey != null) {
            connector.addProperty("identity_npub", identityPubkey);
        }
        String canonical = NostrTransport.canonicalizeJson(connector);
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] connectorSig = signer.sign(hash);

        return transport.sendAttach(avatarLoginXpub, avatar.services(), realmXpub,
                identityPubkey, connectorSig);
    }

    @Override
    public void disconnect() throws Exception {
        if (transport == null || avatarLoginXpub == null) {
            log.warn("No active session to disconnect");
            return;
        }
        transport.sendDetach(avatarLoginXpub);
        transport.close();
        transport = null;
        avatarLoginXpub = null;
        channels.clear();
    }

    /**
     * Handle an incoming service request from the transport layer.
     * Routes to the appropriate {@link ServiceChannel} based on service type.
     */
    JsonObject handleServiceRequest(String serviceType, String method, JsonArray params) {
        log.info("Service request: {}.{}", serviceType, method);

        ServiceChannel channel = channels.get(serviceType);
        if (channel == null) {
            Integer coinType = serviceTypeToCoinType(serviceType);
            if (coinType == null) {
                JsonObject response = new JsonObject();
                response.addProperty("error", "unknown service: " + serviceType);
                return response;
            }
            JsonObject response = new JsonObject();
            response.addProperty("error", "no handler for service: " + serviceType);
            return response;
        }

        JsonObject response = channel.dispatch(method, params);

        // Backward-compatible wire wrapping for request_identities:
        // ServiceChannel returns {"result": [...]}, wire format needs {"result": {"identities": [...]}}
        if ("request_identities".equals(method) && response.has("result")
                && response.get("result").isJsonArray()) {
            JsonObject wrapper = new JsonObject();
            wrapper.add("identities", response.get("result"));
            response.add("result", wrapper);
        }

        return response;
    }

    /**
     * Map a service type string to its protocol coin type.
     */
    static Integer serviceTypeToCoinType(String serviceType) {
        return switch (serviceType) {
            case "ssh" -> Protocol.SSH.coinType();
            case "gpg" -> Protocol.OPENPGP.coinType();
            case "nostr" -> Protocol.NOSTR.coinType();
            default -> null;
        };
    }

    /**
     * Map a protocol coin type to its service type string.
     */
    private static String coinTypeToServiceType(int coinType) {
        if (coinType == Protocol.SSH.coinType()) return "ssh";
        if (coinType == Protocol.OPENPGP.coinType()) return "gpg";
        if (coinType == Protocol.NOSTR.coinType()) return "nostr";
        return null;
    }
}
