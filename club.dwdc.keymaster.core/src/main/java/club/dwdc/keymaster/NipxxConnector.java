package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * NIP-xx transport connector — implements the KeyMaster-Avatar attach/detach
 * handshake over a Nostr relay using NIP-44 encrypted kind-27235 events.
 *
 * <p>Creates its own random realm derivator on each {@link #connect} call.
 * The identity private key never enters this class — signing is delegated
 * to a {@link NostrIdentitySigner} provided by the controller.
 */
public class NipxxConnector implements Connector {
    private static final Logger log = LoggerFactory.getLogger(NipxxConnector.class);

    private final Realm realm;

    private NostrTransport transport;
    private String avatarLoginXpub;
    private final Map<String, ServiceChannel> channels = new HashMap<>();

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

    @Override
    public String connect(AvatarDescriptor avatar, NostrIdentitySigner signer) throws Exception {
        // Create a fresh random realm derivator for this connection
        byte[] realmSeed = new byte[64];
        new SecureRandom().nextBytes(realmSeed);
        Bip32KeyDerivator realmDerivator = new Bip32KeyDerivator(realmSeed);

        int realmIndex = 0;
        byte[] realmPrivKey = realmDerivator.derive(realmIndex);
        byte[] realmPubKey = NostrTransport.computeSchnorrPubKey(realmPrivKey);
        String realmXpub = realmDerivator.deriveXpub(realmIndex);

        this.transport = new NostrTransport(realmPrivKey, realmPubKey);
        transport.setRealmDerivator(realmDerivator, realmIndex);
        transport.setServiceRequestHandler(this::handleServiceRequest);
        transport.connect(avatar.relay());

        this.avatarLoginXpub = avatar.loginXpub();

        // Get identity pubkey and sign the connector hash via the signer
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
