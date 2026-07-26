package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service handler for Nostr identity operations and MLS key management.
 *
 * <p>Provides Nostr methods ({@code get_public_keys}, {@code sign_event},
 * {@code nip04_encrypt}, {@code nip04_decrypt}, {@code nip44_encrypt},
 * {@code nip44_decrypt}) and MLS methods ({@code get_mls_pubkey},
 * {@code mls_sign}, {@code sign_account_identity_proof},
 * {@code mls_hpke_pubkey_at}, {@code mls_hpke_dh}, {@code mls_hpke_decap},
 * {@code mls_next_hpke_init_key}), all backed by a {@link KeyVault} and a
 * list of {@link KeyEntry} objects at coin type 1237 (Nostr).
 *
 * <p>All cryptographic operations that require the private key (ECDH,
 * Schnorr signing, Ed25519 signing, X25519 DH) are delegated to the vault.
 */
public class NostrServiceHandler extends AbstractServiceHandler {

    static {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private static final int H = 0x80000000;

    /** X25519 basepoint (u=9). */
    private static final byte[] X25519_BASEPOINT = new byte[32];
    static {
        X25519_BASEPOINT[0] = 9;
    }

    /** Wrapper for byte[] with proper equals/hashCode, for use as map keys. */
    record ByteArrayKey(byte[] data) {
        @Override public boolean equals(Object o) {
            return o instanceof ByteArrayKey other && Arrays.equals(data, other.data);
        }
        @Override public int hashCode() {
            return Arrays.hashCode(data);
        }
    }

    /** Cached HPKE path info: identity, deviceId, and key index. */
    record HpkePathInfo(String identity, String deviceId, int index) {}

    // MLS caches — populated by get_mls_pubkey, consumed by mls_sign / hpke methods
    private final Map<ByteArrayKey, String> mlsPubkeyToIdentity = new HashMap<>();
    private final Map<ByteArrayKey, String> mlsPubkeyToDeviceId = new HashMap<>();
    private final Map<ByteArrayKey, HpkePathInfo> hpkePubkeyToPath = new HashMap<>();

    public NostrServiceHandler(KeyVault vault, List<KeyEntry> keys) {
        super(vault, keys);
    }

    /**
     * Return the list of Nostr public keys (32-byte x-only Schnorr keys).
     */
    @ServiceMethod(value = "get_public_keys", defaultPolicy = ApprovalPolicy.APPROVE)
    public List<NostrPublicKey> getPublicKeys() {
        checkApproval("get_public_keys", "Nostr public key listing");
        List<NostrPublicKey> result = new ArrayList<>();
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            result.add(new NostrPublicKey(pubResult.data()));
        }
        return result;
    }

    /**
     * Sign a pre-hashed event ID with BIP-340 Schnorr.
     *
     * @throws IllegalArgumentException if no key matches the request's public key
     */
    @ServiceMethod(value = "sign_event", defaultPolicy = ApprovalPolicy.ASK)
    public NostrSignEventResponse signEvent(NostrSignEventRequest request) {
        checkApproval("sign_event", "Nostr event signing");
        KeyEntry key = findKeyByPubkey(request.publicKey());
        VaultResult signResult = vault.execute(KeyVault.FN_SIGN, request.eventHash(), key.toVaultPath());
        if (!signResult.isOk()) {
            throw new IllegalStateException("sign failed: status=" + signResult.status());
        }
        return new NostrSignEventResponse(signResult.data());
    }

    /**
     * Encrypt a message using NIP-04 (ECDH + AES-256-CBC).
     *
     * @throws IllegalArgumentException if no key matches the request's public key
     */
    @ServiceMethod(value = "nip04_encrypt", defaultPolicy = ApprovalPolicy.APPROVE)
    public NostrEncryptResponse nip04Encrypt(NostrEncryptRequest request) {
        checkApproval("nip04_encrypt", "NIP-04 encryption");
        KeyEntry key = findKeyByPubkey(request.publicKey());
        byte[] sharedX = doEcdh(key, request.peerPublicKey());
        return new NostrEncryptResponse(nip04EncryptWithKey(sharedX, request.plaintext()));
    }

    /**
     * Decrypt a message using NIP-04 (ECDH + AES-256-CBC).
     *
     * @throws IllegalArgumentException if no key matches the request's public key
     */
    @ServiceMethod(value = "nip04_decrypt", defaultPolicy = ApprovalPolicy.APPROVE)
    public NostrDecryptResponse nip04Decrypt(NostrDecryptRequest request) {
        checkApproval("nip04_decrypt", "NIP-04 decryption");
        KeyEntry key = findKeyByPubkey(request.publicKey());
        byte[] sharedX = doEcdh(key, request.peerPublicKey());
        return new NostrDecryptResponse(nip04DecryptWithKey(sharedX, request.ciphertext()));
    }

    /**
     * Encrypt a message using NIP-44 (ECDH + HKDF + ChaCha20-Poly1305).
     *
     * @throws IllegalArgumentException if no key matches the request's public key
     */
    @ServiceMethod(value = "nip44_encrypt", defaultPolicy = ApprovalPolicy.APPROVE)
    public NostrEncryptResponse nip44Encrypt(NostrEncryptRequest request) {
        checkApproval("nip44_encrypt", "NIP-44 encryption");
        KeyEntry key = findKeyByPubkey(request.publicKey());
        byte[] sharedX = doEcdh(key, request.peerPublicKey());
        byte[] conversationKey = deriveNip44ConversationKey(sharedX);
        try {
            byte[] nonce = NostrUtil.createRandomByteArray(32);
            String ciphertext = EncryptedPayloads.encrypt(request.plaintext(), conversationKey, nonce);
            return new NostrEncryptResponse(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("NIP-44 encryption failed", e);
        }
    }

    /**
     * Decrypt a message using NIP-44 (ECDH + HKDF + ChaCha20-Poly1305).
     *
     * @throws IllegalArgumentException if no key matches the request's public key
     */
    @ServiceMethod(value = "nip44_decrypt", defaultPolicy = ApprovalPolicy.APPROVE)
    public NostrDecryptResponse nip44Decrypt(NostrDecryptRequest request) {
        checkApproval("nip44_decrypt", "NIP-44 decryption");
        KeyEntry key = findKeyByPubkey(request.publicKey());
        byte[] sharedX = doEcdh(key, request.peerPublicKey());
        byte[] conversationKey = deriveNip44ConversationKey(sharedX);
        try {
            String plaintext = EncryptedPayloads.decrypt(request.ciphertext(), conversationKey);
            return new NostrDecryptResponse(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("NIP-44 decryption failed", e);
        }
    }

    // ==================== MLS methods ====================

    /**
     * Derive the MLS Ed25519 signing public key for a Nostr identity.
     */
    @ServiceMethod(value = "get_mls_pubkey", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsPublicKeyResponse getMlsPubkey(MlsPublicKeyRequest request) {
        checkApproval("get_mls_pubkey", "MLS public key derivation");
        KeyEntry nostrKey = findKeyByPubkey(request.nostrPubkey());
        String identity = nostrKey.metadata().get("identity");
        int[] path = buildMlsSignPath(identity, request.deviceId());
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        if (!result.isOk()) {
            throw new IllegalStateException("MLS pubkey derivation failed: status=" + result.status());
        }
        ByteArrayKey cacheKey = new ByteArrayKey(result.data().clone());
        mlsPubkeyToIdentity.put(cacheKey, identity);
        mlsPubkeyToDeviceId.put(cacheKey, request.deviceId());
        return new MlsPublicKeyResponse(result.data());
    }

    /**
     * Sign data with the MLS Ed25519 signing key.
     */
    @ServiceMethod(value = "mls_sign", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsSignResponse mlsSign(MlsSignRequest request) {
        checkApproval("mls_sign", "MLS Ed25519 signing");
        ByteArrayKey cacheKey = new ByteArrayKey(request.mlsPubkey());
        String identity = mlsPubkeyToIdentity.get(cacheKey);
        if (identity == null) {
            throw new IllegalArgumentException("unknown MLS pubkey — call get_mls_pubkey first");
        }
        String deviceId = mlsPubkeyToDeviceId.get(cacheKey);
        int[] path = buildMlsSignPath(identity, deviceId);
        VaultResult result = vault.execute(KeyVault.FN_SIGN, request.data(), path);
        if (!result.isOk()) {
            throw new IllegalStateException("MLS sign failed: status=" + result.status());
        }
        return new MlsSignResponse(result.data());
    }

    /**
     * Sign an MLS account identity proof (Kind 450 event) with the Nostr key.
     *
     * <p>Constructs a NIP-01 serialized event, SHA-256 hashes it, and Schnorr
     * signs with the Nostr key identified by {@code accountIdentity}.
     */
    @ServiceMethod(value = "sign_account_identity_proof", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsAccountIdentityProofResponse signAccountIdentityProof(MlsAccountIdentityProofRequest request) {
        checkApproval("sign_account_identity_proof", "MLS account identity proof signing");
        KeyEntry nostrKey = findKeyByPubkey(request.accountIdentity());
        String pubkeyHex = NostrUtil.bytesToHex(request.accountIdentity());
        String mlsSigPubkeyHex = NostrUtil.bytesToHex(request.mlsSignaturePublicKey());

        // NIP-01 serialized event for Kind 450
        String serialized = "[0,\"" + pubkeyHex + "\",0,450,"
                + "[[\"mls_signature_public_key\",\"" + mlsSigPubkeyHex + "\"],"
                + "[\"ciphersuite\",\"" + request.ciphersuite() + "\"],"
                + "[\"signature_scheme\",\"" + request.signatureScheme() + "\"]],"
                + "\"\"]";

        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(serialized.getBytes(StandardCharsets.UTF_8));
            VaultResult result = vault.execute(KeyVault.FN_SIGN, hash, nostrKey.toVaultPath());
            if (!result.isOk()) {
                throw new IllegalStateException(
                        "account identity proof sign failed: status=" + result.status());
            }
            return new MlsAccountIdentityProofResponse(result.data());
        } catch (Exception e) {
            if (e instanceof IllegalStateException) throw (IllegalStateException) e;
            throw new IllegalStateException("account identity proof failed", e);
        }
    }

    /**
     * Derive an HPKE X25519 public key at a given index.
     */
    @ServiceMethod(value = "mls_hpke_pubkey_at", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsHpkePubkeyResponse mlsHpkePubkeyAt(MlsHpkePubkeyRequest request) {
        checkApproval("mls_hpke_pubkey_at", "MLS HPKE public key derivation");
        ByteArrayKey cacheKey = new ByteArrayKey(request.mlsPubkey());
        String identity = mlsPubkeyToIdentity.get(cacheKey);
        if (identity == null) {
            throw new IllegalArgumentException("unknown MLS pubkey — call get_mls_pubkey first");
        }
        String deviceId = mlsPubkeyToDeviceId.get(cacheKey);
        int[] path = buildHpkePath(identity, deviceId, request.index());
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, X25519_BASEPOINT, path);
        if (!result.isOk()) {
            throw new IllegalStateException("HPKE pubkey derivation failed: status=" + result.status());
        }
        ByteArrayKey hpkeKey = new ByteArrayKey(result.data().clone());
        hpkePubkeyToPath.put(hpkeKey, new HpkePathInfo(identity, deviceId, request.index()));
        return new MlsHpkePubkeyResponse(result.data());
    }

    /**
     * Perform X25519 DH key agreement with a peer's public key.
     */
    @ServiceMethod(value = "mls_hpke_dh", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsHpkeDhResponse mlsHpkeDh(MlsHpkeDhRequest request) {
        checkApproval("mls_hpke_dh", "MLS HPKE DH key agreement");
        HpkePathInfo info = hpkePubkeyToPath.get(new ByteArrayKey(request.hpkePubkey()));
        if (info == null) {
            throw new IllegalArgumentException("unknown HPKE pubkey — call mls_hpke_pubkey_at first");
        }
        int[] path = buildHpkePath(info.identity(), info.deviceId(), info.index());
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, request.peerPublic(), path);
        if (!result.isOk()) {
            throw new IllegalStateException("HPKE DH failed: status=" + result.status());
        }
        return new MlsHpkeDhResponse(result.data());
    }

    /**
     * Perform X25519 DH decapsulation (same operation as {@code mls_hpke_dh},
     * exposed under a separate wire name for clarity).
     */
    @ServiceMethod(value = "mls_hpke_decap", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsHpkeDhResponse mlsHpkeDecap(MlsHpkeDhRequest request) {
        checkApproval("mls_hpke_decap", "MLS HPKE decapsulation");
        HpkePathInfo info = hpkePubkeyToPath.get(new ByteArrayKey(request.hpkePubkey()));
        if (info == null) {
            throw new IllegalArgumentException("unknown HPKE pubkey — call mls_hpke_pubkey_at first");
        }
        int[] path = buildHpkePath(info.identity(), info.deviceId(), info.index());
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, request.peerPublic(), path);
        if (!result.isOk()) {
            throw new IllegalStateException("HPKE decap failed: status=" + result.status());
        }
        return new MlsHpkeDhResponse(result.data());
    }

    /**
     * Find the next HPKE init key index after the current one.
     *
     * <p>If {@code currentHpkePubkey} is null, returns index 0.
     * Otherwise searches the cache (fallback: brute-force up to 1000 indices).
     */
    @ServiceMethod(value = "mls_next_hpke_init_key", defaultPolicy = ApprovalPolicy.APPROVE)
    public MlsNextInitKeyResponse mlsNextHpkeInitKey(MlsNextInitKeyRequest request) {
        checkApproval("mls_next_hpke_init_key", "MLS next HPKE init key");
        ByteArrayKey mlsKey = new ByteArrayKey(request.mlsPubkey());
        String identity = mlsPubkeyToIdentity.get(mlsKey);
        if (identity == null) {
            throw new IllegalArgumentException("unknown MLS pubkey — call get_mls_pubkey first");
        }
        String deviceId = mlsPubkeyToDeviceId.get(mlsKey);

        int nextIndex;
        if (request.currentHpkePubkey() == null) {
            nextIndex = 0;
        } else {
            ByteArrayKey currentKey = new ByteArrayKey(request.currentHpkePubkey());
            HpkePathInfo cached = hpkePubkeyToPath.get(currentKey);
            if (cached != null) {
                nextIndex = cached.index() + 1;
            } else {
                // Brute-force search for the current key's index
                nextIndex = -1;
                for (int i = 0; i < 1000; i++) {
                    int[] path = buildHpkePath(identity, deviceId, i);
                    VaultResult r = vault.execute(KeyVault.FN_KEY_AGREEMENT, X25519_BASEPOINT, path);
                    if (r.isOk() && Arrays.equals(r.data(), request.currentHpkePubkey())) {
                        nextIndex = i + 1;
                        break;
                    }
                }
                if (nextIndex < 0) {
                    throw new IllegalArgumentException("current HPKE pubkey not found in first 1000 indices");
                }
            }
        }

        int[] path = buildHpkePath(identity, deviceId, nextIndex);
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, X25519_BASEPOINT, path);
        if (!result.isOk()) {
            throw new IllegalStateException("next HPKE init key failed: status=" + result.status());
        }
        ByteArrayKey hpkeKey = new ByteArrayKey(result.data().clone());
        hpkePubkeyToPath.put(hpkeKey, new HpkePathInfo(identity, deviceId, nextIndex));
        return new MlsNextInitKeyResponse(result.data(), nextIndex);
    }

    // -- private helpers --

    /**
     * Mangle an identity for MLS path derivation.
     * If deviceId is present, mangles "identity:deviceId"; otherwise just "identity".
     */
    private static int mlsMangle(String identity, String deviceId) {
        String input = (deviceId != null && !deviceId.isEmpty())
                ? identity + ":" + deviceId
                : identity;
        return Bip32KeyDerivator.mangle(input);
    }

    /**
     * Build the MLS Ed25519 signing key path.
     * {@code m/44'/1242'/mangle'/AlgField(ED25519,0,ROLE_SIGN)'/ConfigField(NONE,0)'}
     */
    private static int[] buildMlsSignPath(String identity, String deviceId) {
        int mangled = mlsMangle(identity, deviceId);
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                mangled | H,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
    }

    /**
     * Build an MLS HPKE key path at the given index.
     * {@code m/44'/1242'/mangle'/AlgField(ED25519,0,ROLE_HPKE)'/ConfigField(NONE,index)'}
     */
    private static int[] buildHpkePath(String identity, String deviceId, int index) {
        int mangled = mlsMangle(identity, deviceId);
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                mangled | H,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_HPKE).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, index).toIndex() | H
        };
    }

    /**
     * Find the key entry whose vault-derived public key matches the given bytes.
     *
     * @throws IllegalArgumentException if no key matches
     */
    private KeyEntry findKeyByPubkey(byte[] publicKey) {
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            if (Arrays.equals(pubResult.data(), publicKey)) {
                return key;
            }
        }
        throw new IllegalArgumentException("key-mismatch");
    }

    /**
     * Perform ECDH key agreement via the vault.
     *
     * @return the raw 32-byte shared x-coordinate
     */
    private byte[] doEcdh(KeyEntry key, byte[] peerPublicKey) {
        VaultResult result = vault.execute(KeyVault.FN_KEY_AGREEMENT, peerPublicKey, key.toVaultPath());
        if (!result.isOk()) {
            throw new IllegalStateException("ECDH failed: status=" + result.status());
        }
        return result.data();
    }

    /**
     * Derive the NIP-44 conversation key from the raw ECDH shared x-coordinate.
     * {@code conversation_key = HKDF-Extract(salt="nip44-v2", ikm=shared_x)}
     */
    private static byte[] deriveNip44ConversationKey(byte[] sharedX) {
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
     * NIP-04 encrypt: AES-256-CBC with the ECDH shared x-coordinate as key.
     * Returns {@code base64(ciphertext)?iv=base64(iv)}.
     */
    private static String nip04EncryptWithKey(byte[] sharedX, String plaintext) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(sharedX, "AES");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted)
                    + "?iv=" + Base64.getEncoder().encodeToString(iv);
        } catch (Exception e) {
            throw new IllegalStateException("NIP-04 encryption failed", e);
        }
    }

    /**
     * NIP-04 decrypt: AES-256-CBC with the ECDH shared x-coordinate as key.
     * Expects {@code base64(ciphertext)?iv=base64(iv)} format.
     */
    private static String nip04DecryptWithKey(byte[] sharedX, String ciphertext) {
        try {
            String[] parts = ciphertext.split("\\?iv=");
            if (parts.length != 2) {
                throw new IllegalArgumentException(
                        "Invalid NIP-04 ciphertext format: expected base64?iv=base64");
            }
            byte[] ct = Base64.getDecoder().decode(parts[0]);
            byte[] iv = Base64.getDecoder().decode(parts[1]);
            SecretKeySpec keySpec = new SecretKeySpec(sharedX, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("NIP-04 decryption failed", e);
        }
    }
}
