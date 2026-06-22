package club.dwdc.keymaster;

import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import club.dwdc.keyexporter.core.OpenPgpSeedDeriver;
import club.dwdc.keyexporter.openpgp.OpenPgpExport;
import club.dwdc.keyexporter.openpgp.OpenPgpExporter;
import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import org.bouncycastle.openpgp.PGPException;

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
    private static final int OPENPGP_COIN = Protocol.OPENPGP.coinType() | H;
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int ALG_ED25519_USER_AUTH =
            new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault;
    private ApprovalHandler approvalHandler;

    private int[] path;
    private byte[] privKey;
    private byte[] pubKey;
    private String pubKeyHex;
    private String currentIdentity;
    private String gpgPublicCertArmor;

    /** BIP-32 derivator for realm (transport) keys — separate from vault identity keys. */
    private final Bip32KeyDerivator realmDerivator;

    private NostrTransport transport;
    private String avatarLoginXpub;

    /**
     * Create a KeyMaster from a ready-to-use KeyVault.
     *
     * <p>Initializes a random realm transport seed.
     * Call {@link #createIdentity(String)} to derive the transport key for an identity.
     *
     * @param vault KeyVault instance for cryptographic operations
     */
    public KeyMaster(KeyVault vault) {
        this.vault = vault;
        byte[] realmSeed = new byte[64];
        new SecureRandom().nextBytes(realmSeed);
        this.realmDerivator = new Bip32KeyDerivator(realmSeed);
    }

    /**
     * Create a KeyMaster from a KeyVault with a specified realm transport seed.
     * This constructor is useful for testing determinism.
     *
     * @param vault     KeyVault instance for cryptographic operations
     * @param realmSeed 64-byte seed for the realm BIP-32 derivator
     */
    public KeyMaster(KeyVault vault, byte[] realmSeed) {
        this.vault = vault;
        this.realmDerivator = new Bip32KeyDerivator(realmSeed);
    }

    /**
     * Set an approval handler for incoming service requests.
     *
     * <p>When set, every service request is passed through the handler before
     * processing. When {@code null} (the default), all requests are auto-approved
     * for backward compatibility.
     *
     * @param handler approval handler, or {@code null} to auto-approve
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
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

        // Generate GPG public cert for this identity.
        // Fixed timestamp for deterministic fingerprints (same identity → same cert).
        // Uses epoch+1 because GnuPG 2.2.x rejects back-signatures with timestamp 0.
        try {
            OpenPgpKeySeeds gpgSeeds = OpenPgpSeedDeriver.derive(vault, identity);
            OpenPgpMetadata gpgMetadata = OpenPgpMetadata.create(
                    identity, identity, identity, Instant.ofEpochSecond(1));
            OpenPgpExport gpgExport = OpenPgpExporter.export(
                    gpgSeeds, gpgMetadata, "keymaster".toCharArray());
            this.gpgPublicCertArmor = gpgExport.publicKeyArmor();
        } catch (PGPException | IOException e) {
            throw new IllegalStateException("Failed to generate GPG cert", e);
        }

        log.info("KeyMaster identity: {}", pubKeyHex);
    }

    /**
     * The Nostr transport public key (hex-encoded, 64 characters).
     */
    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /**
     * Derive the realm xpub at the given realm index.
     * The realm xpub is shared with the Avatar so it can derive service pubkeys.
     *
     * @param realmIndex non-hardened child index (typically 0)
     * @return Base58Check-encoded xpub string
     */
    public String deriveRealmXpub(int realmIndex) {
        return realmDerivator.deriveXpub(realmIndex);
    }

    /**
     * Derive the realm private key bytes at the given realm index.
     * Used as the Nostr transport signing key for the realm.
     *
     * @param realmIndex non-hardened child index (typically 0)
     * @return 32-byte private key
     */
    public byte[] deriveRealmPrivKey(int realmIndex) {
        return realmDerivator.derive(realmIndex);
    }

    /**
     * Derive a service channel private key from the realm.
     * Path: realmIndex / mangle(serviceType) / seq
     *
     * @param realmIndex  realm child index
     * @param serviceType service identifier (e.g. "ssh")
     * @param seq         sequence number
     * @return 32-byte private key
     */
    public byte[] deriveRealmServiceKey(int realmIndex, String serviceType, int seq) {
        int protocolIdx = Bip32KeyDerivator.mangle(serviceType);
        return realmDerivator.derive(realmIndex, protocolIdx, seq);
    }

    /**
     * Get the realm derivator (for use by NostrTransport).
     */
    Bip32KeyDerivator getRealmDerivator() {
        return realmDerivator;
    }

    /**
     * Attach to an Avatar described by the given descriptor.
     *
     * <p>Connects to the relay, sends the attach request, and returns the
     * session event ID. The relay connection is managed internally.
     *
     * @param avatar descriptor with relay URL, login xpub, and services
     * @return session event ID
     */
    public String attach(AvatarDescriptor avatar) throws Exception {
        if (privKey == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }

        // Derive realm keys at index 0 for the transport
        int realmIndex = 0;
        byte[] realmPrivKey = deriveRealmPrivKey(realmIndex);
        byte[] realmPubKey = NostrTransport.computeSchnorrPubKey(realmPrivKey);
        String realmXpub = deriveRealmXpub(realmIndex);

        this.transport = new NostrTransport(realmPrivKey, realmPubKey);
        transport.setRealmDerivator(realmDerivator, realmIndex);
        transport.setServiceRequestHandler(this::handleServiceRequest);
        transport.connect(avatar.relay());

        this.avatarLoginXpub = avatar.loginXpub();
        return transport.sendAttach(avatarLoginXpub, avatar.services(), realmXpub,
                pubKeyHex, privKey);
    }

    /**
     * Detach from the currently attached Avatar and close the relay connection.
     */
    public void detach() throws Exception {
        if (transport == null || avatarLoginXpub == null) {
            log.warn("No active session to detach");
            return;
        }
        transport.sendDetach(avatarLoginXpub);
        transport.close();
        transport = null;
        avatarLoginXpub = null;
    }

    // ==================== Service request handling ====================

    private JsonObject handleServiceRequest(String serviceType, String method, JsonArray params) {
        log.info("Service request: {}.{}", serviceType, method);

        if (approvalHandler != null) {
            String requestType = serviceType + "." + method;
            String detail = buildRequestDetail(serviceType, method, params);
            if (!approvalHandler.approve(requestType, detail)) {
                log.info("Request denied by approval handler: {}", requestType);
                JsonObject response = new JsonObject();
                response.addProperty("error", "request denied by user");
                return response;
            }
        }

        if ("ssh".equals(serviceType)) {
            return handleSshRequest(method, params);
        }

        if ("gpg".equals(serviceType)) {
            return handleGpgRequest(method, params);
        }

        JsonObject response = new JsonObject();
        response.addProperty("error", "unknown service: " + serviceType);
        return response;
    }

    private String buildRequestDetail(String serviceType, String method, JsonArray params) {
        String label = switch (serviceType + "." + method) {
            case "ssh.sign_request" -> "SSH signing request";
            case "ssh.request_identities" -> "SSH identity listing";
            case "gpg.sign_request" -> "GPG signing request";
            case "gpg.request_identities" -> "GPG identity listing";
            case "gpg.get_public_cert" -> "GPG public certificate export";
            default -> serviceType + "." + method;
        };
        if (currentIdentity != null) {
            return label + " for " + currentIdentity;
        }
        return label;
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

    // ==================== GPG service handling ====================

    private JsonObject handleGpgRequest(String method, JsonArray params) {
        return switch (method) {
            case "request_identities" -> handleGpgRequestIdentities();
            case "sign_request" -> handleGpgSignRequest(params);
            case "get_public_cert" -> handleGpgGetPublicCert();
            default -> {
                JsonObject response = new JsonObject();
                response.addProperty("error", "unknown GPG method: " + method);
                yield response;
            }
        };
    }

    private JsonObject handleGpgRequestIdentities() {
        if (currentIdentity == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "no identity set");
            return response;
        }

        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;

        JsonArray identities = new JsonArray();

        // Derive Ed25519 keys for certification (role=0) and signing (role=1) roles
        String[] roleNames = {"certification", "signing"};
        for (int role = 0; role < 2; role++) {
            int algorithm = new AlgField(AlgField.ALG_ED25519, 0, role).toIndex() | H;
            int config = new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;
            int[] gpgPath = new int[]{PURPOSE, OPENPGP_COIN, identityIndex, algorithm, config};

            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, gpgPath);
            if (!pubResult.isOk()) {
                log.error("Failed to derive GPG Ed25519 key for role {}: status={}", role, pubResult.status());
                continue;
            }

            byte[] ed25519PubKey = pubResult.data();
            String pubKeyB64 = Base64.getEncoder().encodeToString(ed25519PubKey);

            JsonObject identity = new JsonObject();
            identity.addProperty("key_type", "ed25519");
            identity.addProperty("public_key", pubKeyB64);
            identity.addProperty("label", currentIdentity + " / " + roleNames[role]);

            identities.add(identity);
            log.info("GPG identity: {} / {} ({} bytes)", currentIdentity, roleNames[role], ed25519PubKey.length);
        }

        JsonObject result = new JsonObject();
        result.add("identities", identities);

        JsonObject response = new JsonObject();
        response.add("result", result);
        return response;
    }

    private JsonObject handleGpgGetPublicCert() {
        if (gpgPublicCertArmor == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "no GPG cert available");
            return response;
        }

        JsonObject result = new JsonObject();
        result.addProperty("public_cert_armor", gpgPublicCertArmor);

        JsonObject response = new JsonObject();
        response.add("result", result);
        return response;
    }

    private JsonObject handleGpgSignRequest(JsonArray params) {
        if (currentIdentity == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "no identity set");
            return response;
        }

        JsonObject reqParams = params.get(0).getAsJsonObject();
        String publicKeyB64 = reqParams.get("public_key").getAsString();
        String dataB64 = reqParams.get("data").getAsString();

        byte[] requestedPubKey = Base64.getDecoder().decode(publicKeyB64);
        byte[] data = Base64.getDecoder().decode(dataB64);

        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;

        // Try to match the requested public key against derived keys at roles 0 and 1
        for (int role = 0; role < 2; role++) {
            int algorithm = new AlgField(AlgField.ALG_ED25519, 0, role).toIndex() | H;
            int config = new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;
            int[] gpgPath = new int[]{PURPOSE, OPENPGP_COIN, identityIndex, algorithm, config};

            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, gpgPath);
            if (!pubResult.isOk()) {
                continue;
            }

            if (java.util.Arrays.equals(pubResult.data(), requestedPubKey)) {
                // Match found — sign with this key's path
                VaultResult signResult = vault.execute(KeyVault.FN_SIGN, data, gpgPath);
                if (!signResult.isOk()) {
                    log.error("GPG sign failed for role {}: status={}", role, signResult.status());
                    JsonObject response = new JsonObject();
                    response.addProperty("error", "sign failed");
                    return response;
                }

                byte[] signature = signResult.data();
                String signatureB64 = Base64.getEncoder().encodeToString(signature);

                log.info("GPG sign: signed {} bytes for {} (role={})", data.length, currentIdentity, role);

                JsonObject result = new JsonObject();
                result.addProperty("signature", signatureB64);

                JsonObject response = new JsonObject();
                response.add("result", result);
                return response;
            }
        }

        log.error("GPG sign: public key does not match any derived key");
        JsonObject response = new JsonObject();
        response.addProperty("error", "key-mismatch");
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
