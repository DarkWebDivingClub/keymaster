package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * NIP-xx transport connector — implements the KeyMaster-Avatar attach/detach
 * handshake over a Nostr relay using NIP-44 encrypted kind-27235 events.
 *
 * <p>Absorbs all transport lifecycle logic previously in {@link KeyMaster}:
 * realm key derivation, {@link NostrTransport} creation, relay connect,
 * attach/detach, and service request routing via {@link ServiceChannel}.
 */
public class NipxxConnector implements Connector {
    private static final Logger log = LoggerFactory.getLogger(NipxxConnector.class);

    private final Session session;
    private final Bip32KeyDerivator realmDerivator;
    private final String identityNpub;
    private final byte[] identityPrivKey;

    private NostrTransport transport;
    private String avatarLoginXpub;
    private final Map<String, ServiceChannel> channels = new HashMap<>();

    /**
     * @param session         session containing active service handlers
     * @param realmDerivator  BIP-32 derivator for realm transport keys
     * @param identityNpub    identity public key (64-char hex)
     * @param identityPrivKey 32-byte identity private key for signing
     */
    public NipxxConnector(Session session, Bip32KeyDerivator realmDerivator,
                          String identityNpub, byte[] identityPrivKey) {
        this.session = session;
        this.realmDerivator = realmDerivator;
        this.identityNpub = identityNpub;
        this.identityPrivKey = identityPrivKey;

        // Build service channels from session handlers (session-based channels
        // resolve handlers lazily, so this is safe even if handlers change later)
        Gson serviceGson = ServiceChannel.createGson();
        for (int coinType : session.getHandlerCoinTypes()) {
            String serviceType = coinTypeToServiceType(coinType);
            if (serviceType != null) {
                channels.put(serviceType, new ServiceChannel(session, coinType, serviceGson));
            }
        }
    }

    @Override
    public String connect(AvatarDescriptor avatar) throws Exception {
        int realmIndex = 0;
        byte[] realmPrivKey = realmDerivator.derive(realmIndex);
        byte[] realmPubKey = NostrTransport.computeSchnorrPubKey(realmPrivKey);
        String realmXpub = realmDerivator.deriveXpub(realmIndex);

        this.transport = new NostrTransport(realmPrivKey, realmPubKey);
        transport.setRealmDerivator(realmDerivator, realmIndex);
        transport.setServiceRequestHandler(this::handleServiceRequest);
        transport.connect(avatar.relay());

        this.avatarLoginXpub = avatar.loginXpub();

        return transport.sendAttach(avatarLoginXpub, avatar.services(), realmXpub,
                identityNpub, identityPrivKey);
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
            // Try mapping service type string to coin type to check if session has a handler
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
            default -> null;
        };
    }

    /**
     * Map a protocol coin type to its service type string.
     */
    private static String coinTypeToServiceType(int coinType) {
        if (coinType == Protocol.SSH.coinType()) return "ssh";
        if (coinType == Protocol.OPENPGP.coinType()) return "gpg";
        return null;
    }
}
