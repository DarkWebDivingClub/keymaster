package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * KeyMaster — passive state holder for the DWDC Key System.
 *
 * <p>Holds the vault, derived identity keys, session, and connector.
 * Orchestration (identity creation, session building, attach/detach)
 * is handled by {@link KeyMasterController}.</p>
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

    private byte[] privKey;
    private String pubKeyHex;
    private String currentIdentity;

    /** BIP-32 derivator for realm (transport) keys — separate from vault identity keys. */
    private final Bip32KeyDerivator realmDerivator;

    private Session session;
    private Connector connector;

    /**
     * Create a KeyMaster from a ready-to-use KeyVault.
     *
     * <p>Initializes a random realm transport seed.
     * Call {@link #deriveIdentity(String)} to derive the transport key for an identity.
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
     * Derive (or re-derive) the Nostr transport key pair for an identity.
     *
     * <p>Only performs vault key derivation — does not build handlers or session.
     * Use {@link KeyMasterController#createIdentity(String)} for full orchestration.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     */
    public void deriveIdentity(String identity) {
        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        int[] path = new int[]{PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};
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
        this.pubKeyHex = NostrUtil.bytesToHex(pubResult.data());

        log.info("KeyMaster identity derived: {}", pubKeyHex);
    }

    /**
     * The Nostr transport public key (hex-encoded, 64 characters).
     */
    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /** The vault backing this KeyMaster. */
    public KeyVault getVault() {
        return vault;
    }

    /** The current identity name, or {@code null} if none derived. */
    public String getCurrentIdentity() {
        return currentIdentity;
    }

    /** The current session, or {@code null}. */
    public Session getSession() {
        return session;
    }

    /** Set the active session. */
    public void setSession(Session session) {
        this.session = session;
    }

    /** The current connector, or {@code null}. */
    public Connector getConnector() {
        return connector;
    }

    /** Set the active connector. */
    public void setConnector(Connector connector) {
        this.connector = connector;
    }

    /** Package-private access to the Nostr identity private key. */
    byte[] getPrivKey() {
        return privKey;
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
     * Returns the SSH authorized_keys line for the current identity's Ed25519 key.
     * Format: {@code ssh-ed25519 <base64-key-blob> <identity>}
     */
    public String getSshAuthorizedKeysLine() {
        if (currentIdentity == null) {
            throw new IllegalStateException("No identity — call deriveIdentity() first");
        }
        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;
        int[] sshPath = new int[]{PURPOSE, SSH_COIN, identityIndex, ALG_ED25519_USER_AUTH, DEFAULT_CONFIG};

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Failed to derive SSH key: status=" + pubResult.status());
        }

        byte[] keyBlob = SshServiceHandler.buildSshEd25519KeyBlob(pubResult.data());
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(keyBlob) + " " + currentIdentity;
    }
}
