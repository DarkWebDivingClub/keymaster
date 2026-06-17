package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * KeyMaster — controller and security authority for the DWDC Key System.
 *
 * <p>Loads a BIP-39 mnemonic, derives a Nostr identity key from the vault,
 * and communicates with an Avatar over a Nostr relay using NIP-44 encrypted
 * kind-27235 events.</p>
 */
public class KeyMaster {
    private static final Logger log = LoggerFactory.getLogger(KeyMaster.class);

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int NOSTR_COIN = Protocol.NOSTR.coinType() | H;
    private static final int SSH_COIN = Protocol.SSH.coinType() | H;
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int ALG_ED25519_USER_AUTH =
            new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault;

    private int[] path;
    private byte[] privKey;
    private byte[] pubKey;
    private String pubKeyHex;
    private String currentIdentity;

    private NostrTransport transport;
    private String avatarPubKeyHex;

    /**
     * Create a KeyMaster from a BIP-39 mnemonic.
     *
     * <p>Creates the vault but does not derive identity keys.
     * Call {@link #createIdentity(String)} to derive the transport key for an identity.
     *
     * @param mnemonic BIP-39 mnemonic phrase
     */
    public KeyMaster(String mnemonic) {
        this.vault = new Bip32KeyVault(mnemonic);
    }

    /**
     * Create (or re-derive) an identity, deriving the Nostr transport key.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     */
    public void createIdentity(String identity) {
        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        this.path = new int[]{PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};
        this.currentIdentity = identity;

        VaultResult seedResult = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        if (!seedResult.isOk()) {
            throw new IllegalStateException("Vault FN_EXPORT_SEED failed: status=" + seedResult.status());
        }
        this.privKey = seedResult.data();

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Vault FN_GET_PUBLIC_KEY failed: status=" + pubResult.status());
        }
        this.pubKey = pubResult.data();
        this.pubKeyHex = NostrUtil.bytesToHex(pubKey);

        log.info("KeyMaster identity: {}", pubKeyHex);
    }

    /**
     * The Nostr transport public key (hex-encoded, 64 characters).
     */
    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /**
     * Attach to an Avatar described by the given descriptor.
     *
     * <p>Connects to the relay, sends the attach request, and returns the
     * session event ID. The relay connection is managed internally.
     *
     * @param avatar descriptor with relay URL, avatar pubkey, and services
     * @return session event ID
     */
    public String attach(AvatarDescriptor avatar) throws Exception {
        if (privKey == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }

        this.transport = new NostrTransport(privKey, pubKey);
        transport.setServiceRequestHandler(this::handleServiceRequest);
        transport.connect(avatar.relay());

        this.avatarPubKeyHex = avatar.pubkey();
        return transport.sendAttach(avatarPubKeyHex, avatar.services());
    }

    /**
     * Detach from the currently attached Avatar and close the relay connection.
     */
    public void detach() throws Exception {
        if (transport == null || avatarPubKeyHex == null) {
            log.warn("No active session to detach");
            return;
        }
        transport.sendDetach(avatarPubKeyHex);
        transport.close();
        transport = null;
        avatarPubKeyHex = null;
    }

    // ==================== Service request handling ====================

    private JsonObject handleServiceRequest(String serviceType, String method, JsonArray params) {
        log.info("Service request: {}.{}", serviceType, method);

        if ("ssh".equals(serviceType)) {
            return handleSshRequest(method, params);
        }

        JsonObject response = new JsonObject();
        response.addProperty("error", "unknown service: " + serviceType);
        return response;
    }

    private JsonObject handleSshRequest(String method, JsonArray params) {
        return switch (method) {
            case "request_identities" -> handleSshRequestIdentities();
            case "sign_request" -> handleSshSignRequest(params);
            default -> {
                JsonObject response = new JsonObject();
                response.addProperty("error", "unknown SSH method: " + method);
                yield response;
            }
        };
    }

    private JsonObject handleSshRequestIdentities() {
        if (currentIdentity == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "no identity set");
            return response;
        }

        // Derive SSH Ed25519 key using the same identity
        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;
        int[] sshPath = new int[]{PURPOSE, SSH_COIN, identityIndex, ALG_ED25519_USER_AUTH, DEFAULT_CONFIG};

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            log.error("Failed to derive SSH Ed25519 key: status={}", pubResult.status());
            JsonObject response = new JsonObject();
            response.addProperty("error", "failed to derive SSH key");
            return response;
        }

        byte[] ed25519PubKey = pubResult.data();
        byte[] keyBlob = buildSshEd25519KeyBlob(ed25519PubKey);
        String keyBlobB64 = Base64.getEncoder().encodeToString(keyBlob);

        log.info("SSH identity: {} ({} bytes key blob)", currentIdentity, keyBlob.length);

        JsonObject identity = new JsonObject();
        identity.addProperty("key_blob", keyBlobB64);
        identity.addProperty("comment", currentIdentity);

        JsonArray identities = new JsonArray();
        identities.add(identity);

        JsonObject result = new JsonObject();
        result.add("identities", identities);

        JsonObject response = new JsonObject();
        response.add("result", result);
        return response;
    }

    private JsonObject handleSshSignRequest(JsonArray params) {
        if (currentIdentity == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "no identity set");
            return response;
        }

        JsonObject reqParams = params.get(0).getAsJsonObject();
        String keyBlobB64 = reqParams.get("key_blob").getAsString();
        String dataB64 = reqParams.get("data").getAsString();

        byte[] data = Base64.getDecoder().decode(dataB64);

        // Derive SSH Ed25519 key path
        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;
        int[] sshPath = new int[]{PURPOSE, SSH_COIN, identityIndex, ALG_ED25519_USER_AUTH, DEFAULT_CONFIG};

        // Verify key_blob matches our derived key
        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            log.error("Failed to derive SSH Ed25519 key for signing: status={}", pubResult.status());
            JsonObject response = new JsonObject();
            response.addProperty("error", "failed to derive SSH key");
            return response;
        }

        byte[] expectedKeyBlob = buildSshEd25519KeyBlob(pubResult.data());
        String expectedKeyBlobB64 = Base64.getEncoder().encodeToString(expectedKeyBlob);
        if (!expectedKeyBlobB64.equals(keyBlobB64)) {
            log.error("SSH sign: key_blob mismatch (expected={}, got={})", expectedKeyBlobB64, keyBlobB64);
            JsonObject response = new JsonObject();
            response.addProperty("error", "key-mismatch");
            return response;
        }

        // Sign using KeyVault
        VaultResult signResult = vault.execute(KeyVault.FN_SIGN, data, sshPath);
        if (!signResult.isOk()) {
            log.error("SSH sign failed: status={}", signResult.status());
            JsonObject response = new JsonObject();
            response.addProperty("error", "sign failed");
            return response;
        }

        byte[] signature = signResult.data();
        String signatureB64 = Base64.getEncoder().encodeToString(signature);

        log.info("SSH sign: signed {} bytes for {}", data.length, currentIdentity);

        JsonObject result = new JsonObject();
        result.addProperty("signature", signatureB64);
        result.addProperty("key_type", "ssh-ed25519");

        JsonObject response = new JsonObject();
        response.add("result", result);
        return response;
    }

    /**
     * Returns the SSH authorized_keys line for the current identity's Ed25519 key.
     * Format: {@code ssh-ed25519 <base64-key-blob> <identity>}
     */
    public String getSshAuthorizedKeysLine() {
        if (currentIdentity == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }
        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;
        int[] sshPath = new int[]{PURPOSE, SSH_COIN, identityIndex, ALG_ED25519_USER_AUTH, DEFAULT_CONFIG};

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Failed to derive SSH key: status=" + pubResult.status());
        }

        byte[] keyBlob = buildSshEd25519KeyBlob(pubResult.data());
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(keyBlob) + " " + currentIdentity;
    }

    /**
     * Build an SSH Ed25519 key blob in SSH wire format:
     * string("ssh-ed25519") + string(pubkey)
     */
    static byte[] buildSshEd25519KeyBlob(byte[] pubKey) {
        byte[] algo = "ssh-ed25519".getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + algo.length + 4 + pubKey.length);
        buf.putInt(algo.length);
        buf.put(algo);
        buf.putInt(pubKey.length);
        buf.put(pubKey);
        return buf.array();
    }
}
