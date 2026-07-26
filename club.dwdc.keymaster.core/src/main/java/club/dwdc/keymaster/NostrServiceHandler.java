package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Service handler for Nostr identity operations.
 *
 * <p>Provides six methods: {@code get_public_keys}, {@code sign_event},
 * {@code nip04_encrypt}, {@code nip04_decrypt}, {@code nip44_encrypt},
 * and {@code nip44_decrypt}, all backed by a {@link KeyVault} and a
 * list of {@link KeyEntry} objects at coin type 1237 (Nostr).
 *
 * <p>All cryptographic operations that require the private key (ECDH,
 * Schnorr signing) are delegated to the vault. The symmetric encryption
 * (AES-256-CBC for NIP-04, ChaCha20 for NIP-44) happens in this handler
 * using the ECDH-derived shared secret.
 */
public class NostrServiceHandler extends AbstractServiceHandler {

    static {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

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

    // -- private helpers --

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
